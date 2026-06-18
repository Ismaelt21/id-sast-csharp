# =============================================================================
#  csharp-sast / core / rules / sinks / sql_sinks.py
# =============================================================================
#
#  CATÁLOGO DE SINKS DE SQL INJECTION PARA C#
#  ─────────────────────────────────────────────
#  Cubre: ADO.NET (SqlCommand, OleDb, Odbc), Microsoft.Data.SqlClient,
#  Entity Framework Core, Entity Framework 6, Dapper, NPoco,
#  NHibernate, ServiceStack OrmLite, y patrones de string building.
#
# =============================================================================

from __future__ import annotations

SQL_INJECTION_SINKS: list[dict] = [

    # =========================================================================
    #  ADO.NET — System.Data.SqlClient
    # =========================================================================
    {
        "id": "SQL-ADO-001", "rule_type": "sink",
        "symbol": "System.Data.SqlClient.SqlCommand..ctor",
        "name": "SqlCommand constructor con query dinámica",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": (
            "SqlCommand construido con una query SQL dinámica en el primer argumento. "
            "Permite SQL Injection completo: lectura de datos, modificación, "
            "y en servidores con xp_cmdshell habilitado, RCE."
        ),
        "remediation": (
            "Usar parámetros: cmd.Parameters.AddWithValue('@param', value). "
            "Nunca concatenar ni interpolar input del usuario en el SQL string."
        ),
        "safe_alternative": "System.Data.SqlClient.SqlParameter",
        "frameworks": ["generic", "aspnetcore", "aspnet_mvc", "wcf"],
        "tags": ["sql", "ado.net", "injection", "owasp-a03"],
    },
    {
        "id": "SQL-ADO-002", "rule_type": "sink",
        "symbol": "System.Data.SqlClient.SqlCommand.CommandText",
        "name": "SqlCommand.CommandText asignado dinámicamente",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": (
            "SqlCommand.CommandText asignado con string dinámico es equivalente "
            "a pasar la query al constructor. Igualmente vulnerable a SQL Injection."
        ),
        "remediation": "Parametrizar la query antes de asignarla a CommandText.",
        "safe_alternative": "System.Data.SqlClient.SqlParameter",
        "frameworks": ["generic", "aspnetcore", "aspnet_mvc"],
        "tags": ["sql", "ado.net", "injection"],
    },
    {
        "id": "SQL-ADO-003", "rule_type": "sink",
        "symbol": "System.Data.SqlClient.SqlDataAdapter..ctor",
        "name": "SqlDataAdapter con query dinámica",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": (
            "SqlDataAdapter acepta la query SELECT en su primer argumento. "
            "Con datos no parametrizados es vulnerable a SQL Injection."
        ),
        "remediation": "Usar SqlDataAdapter con SqlCommand parametrizado como primer argumento.",
        "safe_alternative": "System.Data.SqlClient.SqlCommand con SqlParameter",
        "frameworks": ["generic", "aspnetcore", "aspnet_mvc"],
        "tags": ["sql", "ado.net", "injection"],
    },

    # =========================================================================
    #  ADO.NET — OleDb y Odbc
    # =========================================================================
    {
        "id": "SQL-OLEDB-001", "rule_type": "sink",
        "symbol": "System.Data.OleDb.OleDbCommand..ctor",
        "name": "OleDbCommand con query dinámica",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": (
            "OleDbCommand para bases de datos OLE DB (Access, Excel, Oracle legacy). "
            "Con query SQL dinámica y datos sin parametrizar → SQL Injection."
        ),
        "remediation": "Usar OleDbParameter para parametrizar todas las queries.",
        "safe_alternative": "System.Data.OleDb.OleDbParameter",
        "frameworks": ["generic", "aspnetcore", "aspnet_mvc"],
        "tags": ["sql", "oledb", "injection"],
    },
    {
        "id": "SQL-ODBC-001", "rule_type": "sink",
        "symbol": "System.Data.Odbc.OdbcCommand..ctor",
        "name": "OdbcCommand con query dinámica",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "OdbcCommand usando driver ODBC genérico. La query puede ser vulnerable a SQL Injection.",
        "remediation": "Usar OdbcParameter para parametrizar.",
        "safe_alternative": "System.Data.Odbc.OdbcParameter",
        "frameworks": ["generic"],
        "tags": ["sql", "odbc", "injection"],
    },

    # =========================================================================
    #  Microsoft.Data.SqlClient (driver moderno SQL Server)
    # =========================================================================
    {
        "id": "SQL-MSDATA-001", "rule_type": "sink",
        "symbol": "Microsoft.Data.SqlClient.SqlCommand..ctor",
        "name": "Microsoft.Data.SqlClient.SqlCommand con query dinámica",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": (
            "Driver moderno Microsoft.Data.SqlClient, sucesor de System.Data.SqlClient. "
            "Mismo riesgo de SQL Injection con queries dinámicas."
        ),
        "remediation": "Usar Microsoft.Data.SqlClient.SqlParameter.",
        "safe_alternative": "Microsoft.Data.SqlClient.SqlParameter",
        "frameworks": ["generic", "aspnetcore"],
        "tags": ["sql", "microsoft.data", "injection"],
    },
    {
        "id": "SQL-MSDATA-002", "rule_type": "sink",
        "symbol": "Microsoft.Data.SqlClient.SqlCommand.CommandText",
        "name": "Microsoft.Data SqlCommand.CommandText dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "Asignación dinámica de CommandText en el driver moderno de SQL Server.",
        "remediation": "Parametrizar antes de asignar CommandText.",
        "safe_alternative": "Microsoft.Data.SqlClient.SqlParameter",
        "frameworks": ["generic", "aspnetcore"],
        "tags": ["sql", "microsoft.data", "injection"],
    },

    # =========================================================================
    #  Entity Framework Core
    # =========================================================================
    {
        "id": "SQL-EF-001", "rule_type": "sink",
        "symbol": "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlRaw",
        "name": "EF Core FromSqlRaw con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": (
            "FromSqlRaw no parametriza automáticamente. Si se usa con interpolación "
            "de string ($\"... {userInput}\") o concatenación → SQL Injection. "
            "A diferencia de FromSqlInterpolated, trata la cadena como SQL literal."
        ),
        "remediation": (
            "Reemplazar por FromSqlInterpolated($\"SELECT * WHERE id={id}\") "
            "que parametriza automáticamente las interpolaciones. "
            "O usar LINQ nativo: dbContext.Users.Where(u => u.Id == id)."
        ),
        "safe_alternative": "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlInterpolated",
        "frameworks": ["ef_core", "aspnetcore"],
        "tags": ["sql", "ef-core", "orm", "injection"],
    },
    {
        "id": "SQL-EF-002", "rule_type": "sink",
        "symbol": "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.ExecuteSqlRaw",
        "name": "EF Core ExecuteSqlRaw con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "ExecuteSqlRaw ejecuta SQL sin parametrización automática. Con datos del usuario → SQL Injection.",
        "remediation": (
            "Usar ExecuteSqlInterpolated($\"UPDATE Users SET Name={name} WHERE Id={id}\") "
            "o pasar DbParameter explícito como tercer argumento."
        ),
        "safe_alternative": "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.ExecuteSqlInterpolated",
        "frameworks": ["ef_core", "aspnetcore"],
        "tags": ["sql", "ef-core", "orm", "injection"],
    },
    {
        "id": "SQL-EF-003", "rule_type": "sink",
        "symbol": "Microsoft.EntityFrameworkCore.RelationalDatabaseFacadeExtensions.ExecuteSqlRaw",
        "name": "EF Core Database.ExecuteSqlRaw",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "Database.ExecuteSqlRaw sobre el DbContext — igual de vulnerable que ExecuteSqlRaw.",
        "remediation": "Usar Database.ExecuteSqlInterpolated o pasar DbParameter.",
        "safe_alternative": "ExecuteSqlInterpolated",
        "frameworks": ["ef_core"],
        "tags": ["sql", "ef-core", "orm", "injection"],
    },
    {
        "id": "SQL-EF-004", "rule_type": "sink",
        "symbol": "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlInterpolated",
        "name": "EF Core FromSqlInterpolated con concatenación",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "medium", "severity": "HIGH",
        "cwe": "CWE-89", "cvss_base": 8.1,
        "description": (
            "FromSqlInterpolated es seguro con interpolaciones C# ($\"\"), "
            "pero si se pasa un string ya concatenado pierde la parametrización. "
            "Ejemplo inseguro: FromSqlInterpolated(FormattableStringFactory.Create(sql + userInput))"
        ),
        "remediation": "Asegurar que el argumento sea un FormattableString literal ($\"...\"), no un string ya construido.",
        "safe_alternative": "FromSqlInterpolated con FormattableString literal",
        "frameworks": ["ef_core"],
        "tags": ["sql", "ef-core", "conditional"],
    },

    # =========================================================================
    #  Entity Framework 6
    # =========================================================================
    {
        "id": "SQL-EF6-001", "rule_type": "sink",
        "symbol": "System.Data.Entity.Database.ExecuteSqlCommand",
        "name": "EF6 Database.ExecuteSqlCommand",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "Entity Framework 6 Database.ExecuteSqlCommand con SQL dinámico.",
        "remediation": "Usar SqlParameter como tercer argumento: Database.ExecuteSqlCommand(sql, new SqlParameter('@id', id)).",
        "safe_alternative": "System.Data.SqlClient.SqlParameter",
        "frameworks": ["ef6"],
        "tags": ["sql", "ef6", "orm", "injection"],
    },
    {
        "id": "SQL-EF6-002", "rule_type": "sink",
        "symbol": "System.Data.Entity.Database.SqlQuery",
        "name": "EF6 Database.SqlQuery",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "EF6 Database.SqlQuery ejecuta SQL con tipo de retorno. Vulnerable con strings dinámicos.",
        "remediation": "Pasar SqlParameter como argumento adicional.",
        "safe_alternative": "LINQ nativo de EF",
        "frameworks": ["ef6"],
        "tags": ["sql", "ef6", "orm", "injection"],
    },
    {
        "id": "SQL-EF6-003", "rule_type": "sink",
        "symbol": "System.Data.Entity.DbSet.SqlQuery",
        "name": "EF6 DbSet.SqlQuery",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "EF6 DbSet.SqlQuery ejecuta raw SQL sobre una entidad específica.",
        "remediation": "Usar SqlParameter: dbSet.SqlQuery(\"WHERE Id = @id\", new SqlParameter(\"@id\", id)).",
        "safe_alternative": "LINQ nativo o SqlParameter",
        "frameworks": ["ef6"],
        "tags": ["sql", "ef6", "orm", "injection"],
    },

    # =========================================================================
    #  Dapper
    # =========================================================================
    {
        "id": "SQL-DAPPER-001", "rule_type": "sink",
        "symbol": "Dapper.SqlMapper.Execute",
        "name": "Dapper Execute con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": (
            "Dapper.Execute con SQL construido dinámicamente. "
            "Si el SQL string contiene interpolación del usuario → SQL Injection. "
            "Dapper soporta parámetros anónimos que son seguros."
        ),
        "remediation": (
            "Usar parámetros anónimos: "
            "db.Execute(\"DELETE FROM Users WHERE Id = @Id\", new { Id = userId }). "
            "Nunca interpolar el ID en el string SQL."
        ),
        "safe_alternative": "Dapper con objeto de parámetros anónimo",
        "frameworks": ["dapper", "aspnetcore", "generic"],
        "tags": ["sql", "dapper", "orm", "injection"],
    },
    {
        "id": "SQL-DAPPER-002", "rule_type": "sink",
        "symbol": "Dapper.SqlMapper.Query",
        "name": "Dapper Query con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "Dapper.Query con SQL dinámico construido desde input del usuario.",
        "remediation": "db.Query<T>(\"SELECT * WHERE Id = @Id\", new { Id = id }).",
        "safe_alternative": "Dapper con objeto de parámetros anónimo",
        "frameworks": ["dapper", "aspnetcore", "generic"],
        "tags": ["sql", "dapper", "orm", "injection"],
    },
    {
        "id": "SQL-DAPPER-003", "rule_type": "sink",
        "symbol": "Dapper.SqlMapper.QueryAsync",
        "name": "Dapper QueryAsync con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "Versión asíncrona de Dapper.Query — mismo riesgo.",
        "remediation": "await db.QueryAsync<T>(\"SELECT * WHERE Id = @Id\", new { Id = id }).",
        "safe_alternative": "Dapper con parámetros anónimos",
        "frameworks": ["dapper", "aspnetcore"],
        "tags": ["sql", "dapper", "async", "injection"],
    },
    {
        "id": "SQL-DAPPER-004", "rule_type": "sink",
        "symbol": "Dapper.SqlMapper.ExecuteAsync",
        "name": "Dapper ExecuteAsync con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "Versión asíncrona de Dapper.Execute.",
        "remediation": "await db.ExecuteAsync(sql, new { Param = value }).",
        "safe_alternative": "Dapper con parámetros anónimos",
        "frameworks": ["dapper", "aspnetcore"],
        "tags": ["sql", "dapper", "async", "injection"],
    },
    {
        "id": "SQL-DAPPER-005", "rule_type": "sink",
        "symbol": "Dapper.SqlMapper.QueryFirstOrDefault",
        "name": "Dapper QueryFirstOrDefault con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "Dapper.QueryFirstOrDefault con query SQL dinámica.",
        "remediation": "Parametrizar el SQL con objeto anónimo.",
        "safe_alternative": "Dapper con parámetros anónimos",
        "frameworks": ["dapper", "aspnetcore"],
        "tags": ["sql", "dapper", "injection"],
    },
    {
        "id": "SQL-DAPPER-006", "rule_type": "sink",
        "symbol": "Dapper.SqlMapper.QueryFirstOrDefaultAsync",
        "name": "Dapper QueryFirstOrDefaultAsync con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "Versión asíncrona de QueryFirstOrDefault.",
        "remediation": "Parametrizar el SQL con objeto anónimo.",
        "safe_alternative": "Dapper con parámetros anónimos",
        "frameworks": ["dapper", "aspnetcore"],
        "tags": ["sql", "dapper", "async", "injection"],
    },
    {
        "id": "SQL-DAPPER-007", "rule_type": "sink",
        "symbol": "Dapper.SqlMapper.QuerySingle",
        "name": "Dapper QuerySingle con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "Dapper.QuerySingle con SQL dinámico.",
        "remediation": "Parametrizar el SQL.",
        "safe_alternative": "Dapper con parámetros",
        "frameworks": ["dapper"],
        "tags": ["sql", "dapper", "injection"],
    },
    {
        "id": "SQL-DAPPER-008", "rule_type": "sink",
        "symbol": "Dapper.SqlMapper.QueryMultiple",
        "name": "Dapper QueryMultiple con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "Dapper.QueryMultiple ejecuta múltiples queries en una sola llamada. Con SQL dinámico → SQLi.",
        "remediation": "Parametrizar cada query.",
        "safe_alternative": "Dapper con parámetros",
        "frameworks": ["dapper"],
        "tags": ["sql", "dapper", "injection"],
    },

    # =========================================================================
    #  NPoco y NHibernate
    # =========================================================================
    {
        "id": "SQL-NPOCO-001", "rule_type": "sink",
        "symbol": "NPoco.Database.Execute",
        "name": "NPoco Database.Execute con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "HIGH",
        "cwe": "CWE-89", "cvss_base": 9.0,
        "description": "NPoco Database.Execute con SQL string dinámico.",
        "remediation": "Usar parámetros posicionales: db.Execute(\"WHERE Id = @0\", id).",
        "safe_alternative": "NPoco con parámetros posicionales",
        "frameworks": ["generic"],
        "tags": ["sql", "npoco", "orm", "injection"],
    },
    {
        "id": "SQL-NPOCO-002", "rule_type": "sink",
        "symbol": "NPoco.Database.Fetch",
        "name": "NPoco Database.Fetch con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "HIGH",
        "cwe": "CWE-89", "cvss_base": 9.0,
        "description": "NPoco Database.Fetch con SQL dinámico.",
        "remediation": "Parametrizar: db.Fetch<T>(\"WHERE Id = @0\", id).",
        "safe_alternative": "NPoco con parámetros posicionales",
        "frameworks": ["generic"],
        "tags": ["sql", "npoco", "orm", "injection"],
    },
    {
        "id": "SQL-NHIBERNATE-001", "rule_type": "sink",
        "symbol": "NHibernate.ISession.CreateSQLQuery",
        "name": "NHibernate CreateSQLQuery con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": (
            "NHibernate CreateSQLQuery ejecuta SQL nativo. "
            "Sin usar SetParameter(), el SQL dinámico es vulnerable."
        ),
        "remediation": "Usar SetParameter(\"name\", value) para parametrizar.",
        "safe_alternative": "NHibernate ISQLQuery.SetParameter()",
        "frameworks": ["generic"],
        "tags": ["sql", "nhibernate", "orm", "injection"],
    },
    {
        "id": "SQL-NHIBERNATE-002", "rule_type": "sink",
        "symbol": "NHibernate.ISession.CreateNativeQuery",
        "name": "NHibernate CreateNativeQuery con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": "NHibernate CreateNativeQuery — alias de CreateSQLQuery en versiones modernas.",
        "remediation": "Usar SetParameter() para todos los valores dinámicos.",
        "safe_alternative": "NHibernate con SetParameter()",
        "frameworks": ["generic"],
        "tags": ["sql", "nhibernate", "orm", "injection"],
    },

    # =========================================================================
    #  ServiceStack OrmLite
    # =========================================================================
    {
        "id": "SQL-ORMLITE-001", "rule_type": "sink",
        "symbol": "ServiceStack.OrmLite.OrmLiteReadExpressionsApi.SqlList",
        "name": "OrmLite SqlList con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "HIGH",
        "cwe": "CWE-89", "cvss_base": 9.0,
        "description": "ServiceStack OrmLite SqlList ejecuta SQL nativo.",
        "remediation": "Usar parámetros con objeto anónimo en OrmLite.",
        "safe_alternative": "OrmLite con parámetros",
        "frameworks": ["generic"],
        "tags": ["sql", "ormlite", "servicestack", "injection"],
    },
    {
        "id": "SQL-ORMLITE-002", "rule_type": "sink",
        "symbol": "ServiceStack.OrmLite.OrmLiteWriteCommandExtensions.ExecuteSql",
        "name": "OrmLite ExecuteSql con SQL dinámico",
        "vulnerability": "SQL_INJECTION", "tainted_args": [1],
        "always_vulnerable": False, "confidence": "high", "severity": "HIGH",
        "cwe": "CWE-89", "cvss_base": 9.0,
        "description": "OrmLite ExecuteSql ejecuta SQL arbitrario. Con datos dinámicos → SQLi.",
        "remediation": "Usar parámetros con objetos anónimos.",
        "safe_alternative": "OrmLite con parámetros tipados",
        "frameworks": ["generic"],
        "tags": ["sql", "ormlite", "servicestack", "injection"],
    },

    # =========================================================================
    #  Patrones de string building (detección por DFG)
    # =========================================================================
    {
        "id": "SQL-PATTERN-001", "rule_type": "sink",
        "symbol": "__interpolated_string_sql",
        "name": "String interpolation en contexto SQL",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": (
            "Cadena interpolada ($\"SELECT ... {userInput}\") usada como query SQL. "
            "Es equivalente a concatenar el input en el SQL — SQL Injection."
        ),
        "remediation": (
            "Usar FromSqlInterpolated (EF Core) que parametriza las interpolaciones, "
            "o parámetros con ADO.NET/Dapper."
        ),
        "safe_alternative": "FromSqlInterpolated o SqlParameter",
        "frameworks": ["generic", "aspnetcore", "ef_core"],
        "tags": ["sql", "interpolation", "pattern", "injection"],
    },
    {
        "id": "SQL-PATTERN-002", "rule_type": "sink",
        "symbol": "__string_concat_sql",
        "name": "String concatenation en contexto SQL",
        "vulnerability": "SQL_INJECTION", "tainted_args": [0],
        "always_vulnerable": False, "confidence": "high", "severity": "CRITICAL",
        "cwe": "CWE-89", "cvss_base": 9.8,
        "description": (
            "Concatenación de strings (\"SELECT ... \" + userInput) usada como SQL. "
            "Patrón clásico de SQL Injection desde los años 90."
        ),
        "remediation": "Parametrizar con SqlParameter o equivalente del ORM utilizado.",
        "safe_alternative": "SqlParameter o LINQ",
        "frameworks": ["generic"],
        "tags": ["sql", "concatenation", "pattern", "injection"],
    },
]


def get_sql_sink_rules() -> list[dict]:
    """Retorna el catálogo completo de reglas de SQL Injection."""
    return SQL_INJECTION_SINKS


def get_sql_sink_symbols() -> set[str]:
    """Retorna el conjunto de prefijos de símbolo para lookup O(1)."""
    return {rule["symbol"] for rule in SQL_INJECTION_SINKS}


def get_sql_sink_by_id(rule_id: str) -> dict | None:
    """Retorna una regla específica por su ID."""
    return next((r for r in SQL_INJECTION_SINKS if r["id"] == rule_id), None)


def get_sql_sinks_by_framework(framework: str) -> list[dict]:
    """Retorna las reglas aplicables a un framework específico."""
    return [r for r in SQL_INJECTION_SINKS if framework in r.get("frameworks", [])]