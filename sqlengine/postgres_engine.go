package sqlengine

import (
	"bytes"
	"database/sql"
	"fmt"
	"math/rand"
	"net/url"
	"text/template"
	"time"

	"github.com/lib/pq" // PostgreSQL Driver

	"code.cloudfoundry.org/lager"
)

const (
	pqErrUniqueViolation  = "23505"
	pqErrDuplicateContent = "42710"
	pqErrInternalError    = "XX000"
	pqErrInvalidPassword  = "28P01"
)

type PostgresEngine struct {
	logger            lager.Logger
	db                *sql.DB
	requireSSL        bool
	UsernameGenerator func(seed string) string
}

func NewPostgresEngine(logger lager.Logger) *PostgresEngine {
	return &PostgresEngine{
		logger:            logger.Session("postgres-engine"),
		requireSSL:        true,
		UsernameGenerator: generateUsername,
	}
}

func (d *PostgresEngine) Open(address string, port int64, dbname string, username string, password string) error {
	connectionString := d.URI(address, port, dbname, username, password)
	sanitizedConnectionString := d.URI(address, port, dbname, username, "REDACTED")
	d.logger.Debug("sql-open", lager.Data{"connection-string": sanitizedConnectionString})

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return err
	}

	d.db = db

	// Open() may not actually open the connection so we ping to validate it
	err = d.db.Ping()
	if err != nil {
		// We specifically look for invalid password error and map it to a
		// generic error that can be the same across other engines
		// See: https://www.postgresql.org/docs/9.3/static/errcodes-appendix.html
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == pqErrInvalidPassword {
			// return &LoginFailedError{username}
			return LoginFailedError
		}
		return err
	}

	return nil
}

func (d *PostgresEngine) Close() {
	if d.db != nil {
		d.db.Close()
	}
}

func (d *PostgresEngine) execCreateUser(tx *sql.Tx, bindingID, dbname string, readOnly *bool) (username, password string, err error) {
	//groupname := d.generatePostgresGroup(dbname, readOnly)

	if err = d.ensureRoles(tx, dbname); err != nil {
		return "", "", err
	}

	//WIP - we don't need this anymore
	// if err = d.ensureTrigger(tx, groupname); err != nil {
	// 	return "", "", err
	// }

	username = d.UsernameGenerator(bindingID)
	password = generatePassword()

	if err = d.ensureUser(tx, dbname, username, password); err != nil {
		return "", "", err
	}

	var grantPrivilegesStatement string
	if readOnly != nil && !(*readOnly) {
		d.logger.Debug("grant-privileges", lager.Data{"statement": "adding user to a READ-WRITE role"})
		grantPrivilegesStatement = fmt.Sprintf(`grant "%s" to "%s";`, READ_WRITE_ROLE_NAME, username)
		grantPrivilegesStatement += fmt.Sprintf(`grant "%s" to "%s";`, READ_ONLY_ROLE_NAME, username)
		if err = d.ensureTrigger(tx, READ_WRITE_ROLE_NAME); err != nil {
			return "", "", err
		}
	} else {
		d.logger.Debug("grant-privileges", lager.Data{"statement": "adding user to a READ-ONLY role"})
		grantPrivilegesStatement = fmt.Sprintf(`grant "%s" to "%s"`, READ_ONLY_ROLE_NAME, username)
	}

	d.logger.Debug("grant-privileges", lager.Data{"statement": grantPrivilegesStatement})

	if _, err := tx.Exec(grantPrivilegesStatement); err != nil {
		d.logger.Error("Grant sql-error", err)
		return "", "", err
	}

	return username, password, nil
}

func (d *PostgresEngine) createUser(bindingID, dbname string, readOnly *bool) (username, password string, err error) {
	tx, err := d.db.Begin()
	if err != nil {
		d.logger.Error("sql-error", err)
		return "", "", err
	}
	username, password, err = d.execCreateUser(tx, bindingID, dbname, readOnly)
	if err != nil {
		_ = tx.Rollback()
		return "", "", err
	}
	return username, password, tx.Commit()
}

func (d *PostgresEngine) CreateUser(bindingID, dbname string, readOnly *bool) (username, password string, err error) {
	var pqErr *pq.Error
	tries := 0
	for tries < 10 {
		tries++
		username, password, err := d.createUser(bindingID, dbname, readOnly)
		if err != nil {
			var ok bool
			pqErr, ok = err.(*pq.Error)
			if ok && (pqErr.Code == pqErrInternalError || pqErr.Code == pqErrDuplicateContent || pqErr.Code == pqErrUniqueViolation) {
				time.Sleep(time.Duration(rand.Intn(1500)) * time.Millisecond)
				continue
			}
			return "", "", err
		}
		return username, password, nil
	}
	return "", "", pqErr

}

func (d *PostgresEngine) DropUser(bindingID string) error {
	username := d.UsernameGenerator(bindingID)
	dropUserStatement := fmt.Sprintf(`drop role "%s"`, username)

	_, err := d.db.Exec(dropUserStatement)
	if err == nil {
		return nil
	}

	// When handling unbinds for bindings created before the switch to
	// event-triggers based permissions the `username` won't exist.
	// Also we changed how we generate usernames so we have to try to drop the username generated
	// the old way. If none of the usernames exist then we swallow the error
	if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "42704" {
		d.logger.Info("warning", lager.Data{"warning": "User " + username + " does not exist"})

		username = generateUsernameOld(bindingID)
		dropUserStatement = fmt.Sprintf(`drop role "%s"`, username)
		if _, err = d.db.Exec(dropUserStatement); err != nil {
			if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "42704" {
				d.logger.Info("warning", lager.Data{"warning": "User " + username + " does not exist"})
				return nil
			}
			d.logger.Error("sql-error", err)
			return err
		}

		return nil
	}

	d.logger.Error("sql-error", err)

	return err
}

func (d *PostgresEngine) ResetState() error {
	d.logger.Debug("reset-state.start")

	tx, err := d.db.Begin()
	if err != nil {
		d.logger.Error("sql-error", err)
		return err
	}
	commitCalled := false
	defer func() {
		if !commitCalled {
			tx.Rollback()
		}
	}()

	users, err := d.listNonSuperUsers()
	if err != nil {
		return err
	}

	for _, username := range users {
		dropUserStatement := fmt.Sprintf(`drop role "%s"`, username)
		d.logger.Debug("reset-state", lager.Data{"statement": dropUserStatement})
		if _, err = tx.Exec(dropUserStatement); err != nil {
			d.logger.Error("sql-error", err)
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		d.logger.Error("commit.sql-error", err)
		return err
	}
	commitCalled = true // Prevent Rollback being called in deferred function

	d.logger.Debug("reset-state.finish")

	return nil
}

func (d *PostgresEngine) listNonSuperUsers() ([]string, error) {
	users := []string{}

	rows, err := d.db.Query("select usename from pg_user where usesuper != true and usename != current_user")
	if err != nil {
		d.logger.Error("sql-error", err)
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var username string
		err = rows.Scan(&username)
		if err != nil {
			d.logger.Error("sql-error", err)
			return nil, err
		}
		users = append(users, username)
	}
	return users, nil
}

func (d *PostgresEngine) URI(address string, port int64, dbname string, username string, password string) string {
	uri := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", username, password, address, port, dbname)
	if !d.requireSSL {
		uri = uri + "?sslmode=disable"
	}
	return uri
}

func (d *PostgresEngine) JDBCURI(address string, port int64, dbname string, username string, password string) string {
	params := &url.Values{}
	params.Set("user", username)
	params.Set("password", password)

	if d.requireSSL {
		params.Set("ssl", "true")
	}
	return fmt.Sprintf("jdbc:postgresql://%s:%d/%s?%s", address, port, dbname, params.Encode())
}

const createExtensionPattern = `CREATE EXTENSION IF NOT EXISTS "{{.extension}}"`
const dropExtensionPattern = `DROP EXTENSION IF EXISTS "{{.extension}}"`

func (d *PostgresEngine) CreateExtensions(extensions []string) error {
	for _, extension := range extensions {
		createExtensionTemplate := template.Must(template.New(extension + "Extension").Parse(createExtensionPattern))
		var createExtensionStatement bytes.Buffer
		if err := createExtensionTemplate.Execute(&createExtensionStatement, map[string]string{"extension": extension}); err != nil {
			return err
		}
		if _, err := d.db.Exec(createExtensionStatement.String()); err != nil {
			return err
		}
	}
	return nil
}

func (d *PostgresEngine) DropExtensions(extensions []string) error {
	for _, extension := range extensions {
		dropExtensionTemplate := template.Must(template.New(extension + "Extension").Parse(dropExtensionPattern))
		var dropExtensionStatement bytes.Buffer
		if err := dropExtensionTemplate.Execute(&dropExtensionStatement, map[string]string{"extension": extension}); err != nil {
			return err
		}
		if _, err := d.db.Exec(dropExtensionStatement.String()); err != nil {
			return err
		}
	}
	return nil
}

// generatePostgresGroup produces a deterministic group name. This is because the role
// will be persisted across all application bindings
func (d *PostgresEngine) generatePostgresGroup(dbname string, readOnly *bool) string {
	groupName := dbname + "_manager"
	if readOnly != nil && *readOnly {
		groupName = dbname + "_readonly"
	}

	return groupName
}

const READ_ONLY_ROLE_NAME string = "readonly"
const READ_WRITE_ROLE_NAME string = "readwrite"
const ensureRolesPattern = `
	do
	$body$
	begin
		IF NOT EXISTS (select 1 from pg_catalog.pg_roles where rolname = '{{.read_only_role}}') THEN
			CREATE ROLE "{{.read_only_role}}";
		END IF;
		
		REVOKE ALL ON DATABASE "{{.database}}" FROM PUBLIC;
		GRANT CONNECT ON DATABASE "{{.database}}" TO "{{.read_only_role}}";
		REVOKE CREATE ON SCHEMA public FROM PUBLIC;
		GRANT USAGE ON SCHEMA public TO "{{.read_only_role}}";
		GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{.read_only_role}}";
		ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO "{{.read_only_role}}";
		
		IF NOT EXISTS (select 1 from pg_catalog.pg_roles where rolname = '{{.read_write_role}}') THEN
			CREATE ROLE "{{.read_write_role}}";
		END IF;
		
		GRANT ALL PRIVILEGES ON DATABASE "{{.database}}" TO "{{.read_write_role}}";
		GRANT ALL PRIVILEGES ON SCHEMA public TO "{{.read_write_role}}";
		GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "{{.read_write_role}}";
		ALTER DEFAULT PRIVILEGES FOR ROLE "{{.read_write_role}}" IN SCHEMA public GRANT ALL ON TABLES TO "{{.read_write_role}}";
		GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO "{{.read_write_role}}";
		ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO "{{.read_write_role}}";
		ALTER DEFAULT PRIVILEGES FOR ROLE "{{.read_write_role}}" IN SCHEMA public GRANT SELECT ON TABLES TO "{{.read_only_role}}";
		
	end
	$body$
	`

var ensureRolesTemplate = template.Must(template.New("ensureRoles").Parse(ensureRolesPattern))

func (d *PostgresEngine) ensureRoles(tx *sql.Tx, dbname string) error {
	var ensureRolesStatement bytes.Buffer
	if err := ensureRolesTemplate.Execute(&ensureRolesStatement, map[string]string{
		"read_only_role":  READ_ONLY_ROLE_NAME,
		"read_write_role": READ_WRITE_ROLE_NAME,
		"database":        dbname,
	}); err != nil {
		return err
	}
	d.logger.Debug("ensure-roles", lager.Data{"statement": ensureRolesStatement.String()})

	if _, err := tx.Exec(ensureRolesStatement.String()); err != nil {
		d.logger.Error("sql-error", err)
		return err
	}
	return nil
}

const ensureGroupPattern = `
	do
	$body$
	begin
		IF NOT EXISTS (select 1 from pg_catalog.pg_roles where rolname = '{{.role}}') THEN
			CREATE ROLE "{{.role}}";
		END IF;
	end
	$body$
	`

var ensureGroupTemplate = template.Must(template.New("ensureGroup").Parse(ensureGroupPattern))

func (d *PostgresEngine) ensureGroup(tx *sql.Tx, dbname, groupname string) error {
	var ensureGroupStatement bytes.Buffer
	if err := ensureGroupTemplate.Execute(&ensureGroupStatement, map[string]string{
		"role": groupname,
	}); err != nil {
		return err
	}
	d.logger.Debug("ensure-group", lager.Data{"statement": ensureGroupStatement.String()})

	if _, err := tx.Exec(ensureGroupStatement.String()); err != nil {
		d.logger.Error("sql-error", err)
		return err
	}

	return nil
}

const ensureTriggerPattern = `
	create or replace function reassign_owned() returns event_trigger language plpgsql as $$
	begin
		-- do not execute if member of rds_superuser
		IF EXISTS (select 1 from pg_catalog.pg_roles where rolname = 'rds_superuser')
		AND pg_has_role(current_user, 'rds_superuser', 'member') THEN
			RETURN;
		END IF;

		-- do not execute if not member of manager role
		IF NOT pg_has_role(current_user, '{{.role}}', 'member') THEN
			RETURN;
		END IF;

		-- do not execute if superuser
		IF EXISTS (SELECT 1 FROM pg_user WHERE usename = current_user and usesuper = true) THEN
			RETURN;
		END IF;

		IF EXISTS (select 1 from pg_catalog.pg_roles where rolname = 'readwrite')
		AND pg_has_role(current_user, 'readwrite', 'member') THEN
			EXECUTE 'reassign owned by "' || current_user || '" to "{{.role}}"';
		END IF;
		
	end
	$$;
	`

var ensureTriggerTemplate = template.Must(template.New("ensureTrigger").Parse(ensureTriggerPattern))

func (d *PostgresEngine) ensureTrigger(tx *sql.Tx, groupname string) error {
	var ensureTriggerStatement bytes.Buffer
	if err := ensureTriggerTemplate.Execute(&ensureTriggerStatement, map[string]string{
		"role": groupname,
	}); err != nil {
		return err
	}

	cmds := []string{
		ensureTriggerStatement.String(),
		`drop event trigger if exists reassign_owned;`,
		`create event trigger reassign_owned on ddl_command_end execute procedure reassign_owned();`,
	}

	for _, cmd := range cmds {
		d.logger.Debug("ensure-trigger", lager.Data{"statement": cmd})
		_, err := tx.Exec(cmd)
		if err != nil {
			d.logger.Error("sql-error", err)
			return err
		}
	}

	return nil
}

const ensureCreateUserPattern = `
	DO
	$body$
	BEGIN
	   IF NOT EXISTS (
		  SELECT *
		  FROM   pg_catalog.pg_user
		  WHERE  usename = '{{.user}}') THEN

		  CREATE USER {{.user}} WITH PASSWORD '{{.password}}';
	   END IF;
	END
	$body$;`

var ensureCreateUserTemplate = template.Must(template.New("ensureUser").Parse(ensureCreateUserPattern))

func (d *PostgresEngine) ensureUser(tx *sql.Tx, dbname string, username string, password string) error {
	var ensureUserStatement bytes.Buffer
	if err := ensureCreateUserTemplate.Execute(&ensureUserStatement, map[string]string{
		"password": password,
		"user":     username,
	}); err != nil {
		return err
	}
	d.logger.Debug("ensure-user-with-password", lager.Data{"statement": ensureUserStatement.String()})

	var ensureUserStatementSanitized bytes.Buffer
	if err := ensureCreateUserTemplate.Execute(&ensureUserStatementSanitized, map[string]string{
		"password": "REDACTED",
		"user":     username,
	}); err != nil {
		return err
	}
	d.logger.Debug("ensure-user", lager.Data{"statement": ensureUserStatementSanitized.String()})

	if _, err := tx.Exec(ensureUserStatement.String()); err != nil {
		d.logger.Error("sql-error", err)
		return err
	}

	return nil
}
