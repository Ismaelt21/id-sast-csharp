# =============================================================================
#  csharp-sast / core / rules / sanitizers / parameterization_sanitizers.py
# =============================================================================
#
#  CATÁLOGO DE SANITIZADORES DE PARAMETRIZACIÓN PARA C#
#  ──────────────────────────────────────────────────────
#  Define los métodos de .NET que separan el código de los datos mediante
#  parametrización, haciendo imposible que los datos del usuario modifiquen
#  la estructura del comando, query o protocolo.
#
#  PARAMETRIZACIÓN VS VALIDACIÓN VS ENCODING (distinción crítica):
#
#    • Encoding (encoding_sanitizers.py):
#        Transforma caracteres peligrosos en representaciones seguras.
#        El dato sigue siendo "sucio" — solo el encoded es seguro en ese contexto.
#        Ejemplo: HtmlEncode("<script>") → "&lt;script&gt;"
#
#    • Validación (validation_sanitizers.py):
#        Verifica que el dato cumple un contrato de tipo o formato.
#        Si pasa → se considera seguro. Si falla → se rechaza.
#        Ejemplo: int.TryParse("123") → 123 (no puede contener SQL)
#
#    • Parametrización (este módulo):
#        Separa ESTRUCTURALMENTE el código de los datos.
#        El driver/framework trata el parámetro como DATO PURO,
#        nunca como parte del código ejecutable.
#        Es la defensa más robusta contra injection — no depende
#        de que el dato sea "seguro", sino de que NUNCA se concatena.
#        Ejemplo: SqlCommand("SELECT * WHERE Id=@id") + cmd.Parameters.AddWithValue("@id", userInput)
#        → Incluso si userInput = "'; DROP TABLE Users;--", la query es SEGURA.
#
#  POR QUÉ LA PARAMETRIZACIÓN ES LA DEFENSA MÁS FUERTE:
#    La validación y el encoding pueden fallar con:
#      • Ataques de bypass de encoding (unicode normalization)
#      • Caracteres especiales no contemplados en la blacklist
#      • Cambios de contexto (HTML encoding en JS context)
#      • Errores humanos en la implementación del sanitizador
#
#    La parametrización es estructuralmente segura:
#      El driver de base de datos NUNCA interpreta el valor del parámetro
#      como SQL — es físicamente imposible el injection.
#      El defecto de seguridad solo ocurre si se MEZCLA parametrización
#      con concatenación (e.g., SqlCommand("SELECT * WHERE col=" + param_value)).
#
#  CONFIDENCE EN PARAMETRIZACIÓN:
#    Los sanitizadores de parametrización tienen confidence muy alta (0.95-1.0)
#    porque el mecanismo de protección es estructural, no heurístico.
#    La única limitación es el uso incorrecto del API.
#
#  CAMPOS (idénticos a encoding_sanitizers.py y validation_sanitizers.py):
#    id, rule_type, symbol, name, sanitizes, sanitizer_type,
#    encoding_context, confidence, limitations, description,
#    frameworks, tags
#
#  NOTA SOBRE encoding_context EN PARAMETRIZACIÓN:
#    Para parametrización, encoding_context indica el mecanismo específico
#    de separación usado: sql_parameter, orm_parameterized_query,
#    stored_procedure, type_safe_deserialization, etc.
#
# =============================================================================

from __future__ import annotations

PARAMETERIZATION_SANITIZERS: list[dict] = [

    # =========================================================================
    #  SECCIÓN 1: ADO.NET — System.Data.SqlClient (driver clásico SQL Server)
    #  La parametrización más fundamental en .NET — separa SQL de datos.
    # =========================================================================

    {
        "id":              "SAN-PARAM-001",
        "rule_type":       "sanitizer",
        "symbol":          "System.Data.SqlClient.SqlParameter",
        "name":            "SqlParameter — parametrización ADO.NET (SQL Server clásico)",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      1.0,
        "limitations": (
            "Confidence 1.0 — la parametrización es estructuralmente segura. "
            "ADVERTENCIA CRÍTICA: debe usarse para CADA parámetro del SQL. "
            "Un solo parámetro sin parametrizar invalida la protección completa: "
            "'SELECT * WHERE Type=@type AND Name=' + userInput → VULNERABLE. "
            "No mezclar parametrización con concatenación de strings."
        ),
        "description": (
            "System.Data.SqlClient.SqlParameter separa completamente el código SQL "
            "de los datos del usuario. El driver de SQL Server trata el valor del "
            "parámetro como dato puro — nunca lo interpreta como SQL. "
            "Incluso si el valor es '; DROP TABLE Users;--, la query es segura. "
            "Uso correcto: "
            "var cmd = new SqlCommand('SELECT * WHERE Id = @id', conn); "
            "cmd.Parameters.AddWithValue('@id', userId); "
            "Alternativa: cmd.Parameters.Add(new SqlParameter('@id', SqlDbType.Int) { Value = userId });"
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc", "wcf"],
        "tags":            ["parameterization", "sql", "ado.net", "sqlserver",
                            "gold-standard", "owasp-a03"],
    },
    {
        "id":              "SAN-PARAM-002",
        "rule_type":       "sanitizer",
        "symbol":          "System.Data.SqlClient.SqlCommand.Parameters",
        "name":            "SqlCommand.Parameters — colección de parámetros ADO.NET",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      1.0,
        "limitations": (
            "Mismas limitaciones que SqlParameter. "
            "SqlCommand.Parameters es la colección — el sanitizador real "
            "es el SqlParameter que se añade, no la colección en sí."
        ),
        "description": (
            "SqlCommand.Parameters.AddWithValue('@param', value) — "
            "forma abreviada de añadir SqlParameter. "
            "Equivalente en seguridad a crear SqlParameter explícitamente."
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":            ["parameterization", "sql", "ado.net", "addwithvalue"],
    },
    {
        "id":              "SAN-PARAM-003",
        "rule_type":       "sanitizer",
        "symbol":          "System.Data.SqlClient.SqlDataAdapter",
        "name":            "SqlDataAdapter con SqlCommand parametrizado",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.95,
        "limitations": (
            "Confidence 0.95 — seguro si el SqlCommand subyacente "
            "está correctamente parametrizado. "
            "Si el SqlCommand usa concatenación → no protege."
        ),
        "description": (
            "SqlDataAdapter con un SqlCommand parametrizado como SelectCommand. "
            "La parametrización está en el SqlCommand — el Adapter hereda la protección."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["parameterization", "sql", "ado.net", "adapter"],
    },

    # =========================================================================
    #  SECCIÓN 2: Microsoft.Data.SqlClient (driver moderno SQL Server)
    # =========================================================================

    {
        "id":              "SAN-PARAM-004",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.Data.SqlClient.SqlParameter",
        "name":            "SqlParameter — parametrización ADO.NET (driver moderno)",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      1.0,
        "limitations": (
            "Mismas limitaciones que System.Data.SqlClient.SqlParameter. "
            "El driver moderno reemplaza al clásico en nuevas aplicaciones."
        ),
        "description": (
            "Microsoft.Data.SqlClient.SqlParameter — driver moderno de SQL Server. "
            "Misma seguridad y API que System.Data.SqlClient.SqlParameter. "
            "Usar en aplicaciones .NET Core y .NET 5+ donde "
            "System.Data.SqlClient está obsoleto."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["parameterization", "sql", "microsoft.data", "modern"],
    },
    {
        "id":              "SAN-PARAM-005",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.Data.SqlClient.SqlCommand.Parameters",
        "name":            "SqlCommand.Parameters (driver moderno) — AddWithValue",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      1.0,
        "limitations":     "Mismas limitaciones que la versión clásica.",
        "description": (
            "Microsoft.Data.SqlClient.SqlCommand.Parameters — "
            "colección de parámetros del driver moderno."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["parameterization", "sql", "microsoft.data", "addwithvalue"],
    },

    # =========================================================================
    #  SECCIÓN 3: OleDb y Odbc — otros drivers ADO.NET
    # =========================================================================

    {
        "id":              "SAN-PARAM-006",
        "rule_type":       "sanitizer",
        "symbol":          "System.Data.OleDb.OleDbParameter",
        "name":            "OleDbParameter — parametrización para OLE DB",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      1.0,
        "limitations": (
            "Confidence 1.0 — OleDb usa ? como placeholder de parámetro, "
            "no @nombre. La parametrización es igualmente segura. "
            "OleDb cubre: Access, Excel, Oracle legacy, SQL Server legacy."
        ),
        "description": (
            "System.Data.OleDb.OleDbParameter — parametrización para bases de datos OLE DB. "
            "Usa ? como placeholder posicional en lugar de @nombre. "
            "Ejemplo: new OleDbCommand('SELECT * WHERE Id = ?', conn) "
            "+ cmd.Parameters.Add(new OleDbParameter { Value = userId })."
        ),
        "frameworks":      ["generic"],
        "tags":            ["parameterization", "sql", "oledb", "access", "excel"],
    },
    {
        "id":              "SAN-PARAM-007",
        "rule_type":       "sanitizer",
        "symbol":          "System.Data.Odbc.OdbcParameter",
        "name":            "OdbcParameter — parametrización para ODBC",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      1.0,
        "limitations": (
            "Confidence 1.0 — mismo mecanismo que OleDb, usa ? como placeholder. "
            "ODBC soporta: MySQL, PostgreSQL, SQLite y otros via driver genérico."
        ),
        "description": (
            "System.Data.Odbc.OdbcParameter — parametrización para el driver ODBC genérico. "
            "Cubre bases de datos no soportadas directamente por drivers nativos."
        ),
        "frameworks":      ["generic"],
        "tags":            ["parameterization", "sql", "odbc", "generic-driver"],
    },

    # =========================================================================
    #  SECCIÓN 4: Entity Framework Core — queries parametrizadas en ORM
    # =========================================================================

    {
        "id":              "SAN-PARAM-008",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSqlInterpolated",
        "name":            "EF Core FromSqlInterpolated — parametrización automática de interpolaciones",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["orm_parameterized_query"],
        "confidence":      0.98,
        "limitations": (
            "Confidence 0.98 — seguro para interpolaciones C# estándar ($\"...\"). "
            "ADVERTENCIA: NO pasar un FormattableString ya construido dinámicamente "
            "con FromSqlRaw — eso pierde la parametrización. "
            "Incorrecto: var sql = $'SELECT WHERE id={id}'; db.FromSqlInterpolated(sql) ← SEGURO "
            "Incorrecto: var sql = 'SELECT WHERE id=' + id; db.FromSqlRaw(sql) ← VULNERABLE "
            "EF Core usa DbParameter internamente para cada interpolación."
        ),
        "description": (
            "EF Core FromSqlInterpolated() acepta una FormattableString y convierte "
            "automáticamente cada interpolación en un DbParameter. "
            "Es la alternativa segura a FromSqlRaw. "
            "Uso: db.Users.FromSqlInterpolated($'SELECT * WHERE Id = {userId}') "
            "EF Core extrae el valor de userId y lo pasa como parámetro al driver."
        ),
        "frameworks":      ["ef_core", "aspnetcore"],
        "tags":            ["parameterization", "sql", "ef-core", "orm",
                            "interpolation", "recommended"],
    },
    {
        "id":              "SAN-PARAM-009",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.ExecuteSqlInterpolated",
        "name":            "EF Core ExecuteSqlInterpolated — ejecución parametrizada automática",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["orm_parameterized_query"],
        "confidence":      0.98,
        "limitations": (
            "Mismas limitaciones que FromSqlInterpolated. "
            "Solo seguro con FormattableString literal ($\"...\"), "
            "no con string ya construido."
        ),
        "description": (
            "EF Core ExecuteSqlInterpolated() — versión parametrizada de ExecuteSqlRaw. "
            "Para comandos DML (INSERT, UPDATE, DELETE) con datos del usuario."
        ),
        "frameworks":      ["ef_core", "aspnetcore"],
        "tags":            ["parameterization", "sql", "ef-core", "dml", "recommended"],
    },
    {
        "id":              "SAN-PARAM-010",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.EntityFrameworkCore.DbContext.Database.ExecuteSqlInterpolated",
        "name":            "EF Core Database.ExecuteSqlInterpolated — acceso directo parametrizado",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["orm_parameterized_query"],
        "confidence":      0.98,
        "limitations":     "Mismas limitaciones — solo seguro con FormattableString literal.",
        "description": (
            "Database.ExecuteSqlInterpolated() en el DbContext — "
            "acceso al ejecutor de SQL parametrizado del DbContext directamente."
        ),
        "frameworks":      ["ef_core"],
        "tags":            ["parameterization", "sql", "ef-core", "dbcontext"],
    },
    {
        "id":              "SAN-PARAM-011",
        "rule_type":       "sanitizer",
        "symbol":          "Microsoft.EntityFrameworkCore.RelationalQueryableExtensions.FromSql",
        "name":            "EF Core FromSql — método unificado parametrizado (EF Core 8+)",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["orm_parameterized_query"],
        "confidence":      0.98,
        "limitations": (
            "Disponible desde EF Core 8.0 como reemplazo unificado de "
            "FromSqlRaw y FromSqlInterpolated. "
            "Acepta FormattableString — parametrización automática de interpolaciones."
        ),
        "description": (
            "EF Core 8+ FromSql() — el nuevo método unificado que reemplaza "
            "FromSqlRaw y FromSqlInterpolated con una API más limpia. "
            "db.Users.FromSql($'SELECT * WHERE Id = {userId}') es seguro."
        ),
        "frameworks":      ["ef_core", "aspnetcore"],
        "tags":            ["parameterization", "sql", "ef-core", "ef8", "unified"],
    },

    # =========================================================================
    #  SECCIÓN 5: LINQ — queries tipadas (sin SQL crudo)
    # =========================================================================

    {
        "id":              "SAN-PARAM-012",
        "rule_type":       "sanitizer",
        "symbol":          "System.Linq.Queryable.Where",
        "name":            "LINQ Where — query tipada sin SQL crudo",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["orm_linq_query"],
        "confidence":      1.0,
        "limitations": (
            "Confidence 1.0 — LINQ tipado es imposible de inyectar porque "
            "las expresiones lambda se traducen a SQL parametrizado automáticamente. "
            "NUNCA pueden contener SQL injection por diseño. "
            "No aplica si se usa LINQ to Objects con SQL manual."
        ),
        "description": (
            "LINQ Queryable.Where con expresiones lambda es inmune a SQL injection. "
            "EF Core/LINQ traduce 'db.Users.Where(u => u.Id == userId)' a "
            "'SELECT * FROM Users WHERE Id = @p0' con parámetros automáticos. "
            "Es el método más seguro y recomendado para queries en EF Core."
        ),
        "frameworks":      ["ef_core", "ef6", "aspnetcore"],
        "tags":            ["parameterization", "sql", "linq", "orm",
                            "type-safe", "gold-standard"],
    },
    {
        "id":              "SAN-PARAM-013",
        "rule_type":       "sanitizer",
        "symbol":          "System.Linq.Queryable.Select",
        "name":            "LINQ Select — proyección tipada",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["orm_linq_query"],
        "confidence":      1.0,
        "limitations":     "Mismas limitaciones que LINQ Where — completamente seguro por diseño.",
        "description": (
            "LINQ Queryable.Select — proyección tipada sin SQL crudo. "
            "Todas las operaciones LINQ sobre IQueryable<T> son traducidas "
            "a SQL parametrizado por el ORM."
        ),
        "frameworks":      ["ef_core", "ef6", "aspnetcore"],
        "tags":            ["parameterization", "sql", "linq", "projection", "type-safe"],
    },
    {
        "id":              "SAN-PARAM-014",
        "rule_type":       "sanitizer",
        "symbol":          "System.Linq.Queryable.FirstOrDefault",
        "name":            "LINQ FirstOrDefault — consulta tipada de un elemento",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["orm_linq_query"],
        "confidence":      1.0,
        "limitations":     "Completamente seguro — expresión lambda sin SQL crudo.",
        "description": (
            "LINQ FirstOrDefault() con predicado lambda — traducido a SQL parametrizado. "
            "db.Users.FirstOrDefault(u => u.Email == email) es completamente seguro."
        ),
        "frameworks":      ["ef_core", "ef6", "aspnetcore"],
        "tags":            ["parameterization", "sql", "linq", "type-safe"],
    },

    # =========================================================================
    #  SECCIÓN 6: Dapper — micro-ORM con parametrización por objeto anónimo
    # =========================================================================

    {
        "id":              "SAN-PARAM-015",
        "rule_type":       "sanitizer",
        "symbol":          "Dapper.SqlMapper.Execute",
        "name":            "Dapper Execute con objeto anónimo de parámetros",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.98,
        "limitations": (
            "Confidence 0.98 — seguro SOLO cuando se usa el segundo argumento "
            "como objeto de parámetros anónimo. "
            "El SQL en el primer argumento DEBE ser estático (hardcodeado). "
            "Incorrecto: db.Execute(sql + userInput, new { Id = id }) ← VULNERABLE "
            "Correcto: db.Execute('DELETE WHERE Id = @Id', new { Id = id }) ← SEGURO "
            "Dapper mapea las propiedades del objeto anónimo a parámetros del SQL."
        ),
        "description": (
            "Dapper.Execute() con objeto anónimo — parametrización vía anonymous object. "
            "db.Execute('DELETE FROM Users WHERE Id = @Id', new { Id = userId }) "
            "Dapper usa ADO.NET DbParameter internamente para cada propiedad del objeto. "
            "El SQL debe ser un template estático; el objeto anónimo contiene los datos."
        ),
        "frameworks":      ["dapper", "generic", "aspnetcore"],
        "tags":            ["parameterization", "sql", "dapper", "anonymous-object",
                            "micro-orm"],
    },
    {
        "id":              "SAN-PARAM-016",
        "rule_type":       "sanitizer",
        "symbol":          "Dapper.SqlMapper.Query",
        "name":            "Dapper Query con objeto anónimo de parámetros",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.98,
        "limitations": (
            "Mismas limitaciones que Dapper.Execute. "
            "El SQL debe ser un template estático."
        ),
        "description": (
            "Dapper.Query<T>() con objeto anónimo de parámetros — "
            "db.Query<User>('SELECT * WHERE Id = @Id', new { Id = userId })."
        ),
        "frameworks":      ["dapper", "generic", "aspnetcore"],
        "tags":            ["parameterization", "sql", "dapper", "query"],
    },
    {
        "id":              "SAN-PARAM-017",
        "rule_type":       "sanitizer",
        "symbol":          "Dapper.SqlMapper.QueryAsync",
        "name":            "Dapper QueryAsync con parámetros anónimos",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.98,
        "limitations":     "Mismas limitaciones que Dapper.Query.",
        "description": (
            "Dapper.QueryAsync<T>() — versión asíncrona con misma parametrización. "
            "await db.QueryAsync<User>('SELECT * WHERE Id = @Id', new { Id = userId })."
        ),
        "frameworks":      ["dapper", "aspnetcore"],
        "tags":            ["parameterization", "sql", "dapper", "async"],
    },
    {
        "id":              "SAN-PARAM-018",
        "rule_type":       "sanitizer",
        "symbol":          "Dapper.SqlMapper.ExecuteAsync",
        "name":            "Dapper ExecuteAsync con parámetros anónimos",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.98,
        "limitations":     "Mismas limitaciones que Dapper.Execute.",
        "description": (
            "Dapper.ExecuteAsync() — versión asíncrona con misma parametrización."
        ),
        "frameworks":      ["dapper", "aspnetcore"],
        "tags":            ["parameterization", "sql", "dapper", "async", "dml"],
    },
    {
        "id":              "SAN-PARAM-019",
        "rule_type":       "sanitizer",
        "symbol":          "Dapper.DynamicParameters",
        "name":            "Dapper DynamicParameters — parámetros dinámicos tipados",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.97,
        "limitations": (
            "Confidence 0.97 — DynamicParameters construye parámetros dinámicamente "
            "con tipo y dirección. "
            "Tan seguro como el objeto anónimo pero más flexible para "
            "stored procedures con OUTPUT parameters."
        ),
        "description": (
            "Dapper.DynamicParameters permite construir parámetros dinámicamente: "
            "var p = new DynamicParameters(); "
            "p.Add('@Id', userId, DbType.Int32, ParameterDirection.Input); "
            "db.Execute('usp_GetUser', p, commandType: CommandType.StoredProcedure)."
        ),
        "frameworks":      ["dapper"],
        "tags":            ["parameterization", "sql", "dapper", "dynamic",
                            "stored-procedure"],
    },

    # =========================================================================
    #  SECCIÓN 7: Stored Procedures — commands de procedimiento almacenado
    # =========================================================================

    {
        "id":              "SAN-PARAM-020",
        "rule_type":       "sanitizer",
        "symbol":          "System.Data.CommandType.StoredProcedure",
        "name":            "CommandType.StoredProcedure — ejecución de stored procedure",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["stored_procedure"],
        "confidence":      0.97,
        "limitations": (
            "Confidence 0.97 — un stored procedure llamado con parámetros es seguro. "
            "EXCEPCIÓN: si el stored procedure internamente usa SQL dinámico "
            "(EXEC(@sql)) con los parámetros → vulnerable dentro del SP. "
            "El nombre del stored procedure NO debe ser dinámico."
        ),
        "description": (
            "CommandType.StoredProcedure con parámetros nombrados llama a un "
            "procedimiento almacenado con parámetros separados del código SQL. "
            "El nombre del SP debe ser hardcodeado. Los parámetros del SP "
            "son pasados como DbParameter → separación estructural."
        ),
        "frameworks":      ["generic", "aspnetcore", "aspnet_mvc"],
        "tags":            ["parameterization", "sql", "stored-procedure", "sp"],
    },
    {
        "id":              "SAN-PARAM-021",
        "rule_type":       "sanitizer",
        "symbol":          "System.Data.SqlClient.SqlCommand.CommandType",
        "name":            "SqlCommand.CommandType.StoredProcedure — configuración de SP",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["stored_procedure"],
        "confidence":      0.97,
        "limitations":     "Mismas limitaciones que CommandType.StoredProcedure.",
        "description": (
            "Configurar SqlCommand.CommandType = CommandType.StoredProcedure "
            "activa el modo de ejecución de procedimiento almacenado."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["parameterization", "sql", "stored-procedure", "ado.net"],
    },

    # =========================================================================
    #  SECCIÓN 8: Entity Framework 6 — ORM legacy
    # =========================================================================

    {
        "id":              "SAN-PARAM-022",
        "rule_type":       "sanitizer",
        "symbol":          "System.Data.Entity.Database.SqlQuery",
        "name":            "EF6 Database.SqlQuery con DbParameter — parametrización manual EF6",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.95,
        "limitations": (
            "Confidence 0.95 — seguro SOLO si se pasan DbParameter explícitamente. "
            "Incorrecto: db.Database.SqlQuery<User>('SELECT * WHERE Id=' + id) ← VULNERABLE "
            "Correcto: db.Database.SqlQuery<User>('SELECT * WHERE Id=@id', new SqlParameter('@id', id)) ← SEGURO"
        ),
        "description": (
            "EF6 Database.SqlQuery<T>() con SqlParameter explícito. "
            "db.Database.SqlQuery<User>('SELECT * WHERE Id = @id', "
            "new SqlParameter('@id', userId))."
        ),
        "frameworks":      ["ef6"],
        "tags":            ["parameterization", "sql", "ef6", "legacy"],
    },
    {
        "id":              "SAN-PARAM-023",
        "rule_type":       "sanitizer",
        "symbol":          "System.Data.Entity.Database.ExecuteSqlCommand",
        "name":            "EF6 Database.ExecuteSqlCommand con DbParameter",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.95,
        "limitations": (
            "Confidence 0.95 — misma condición que SqlQuery. "
            "Requiere pasar DbParameter explícitos como argumentos adicionales."
        ),
        "description": (
            "EF6 Database.ExecuteSqlCommand() con parámetros explícitos. "
            "db.Database.ExecuteSqlCommand('UPDATE Users SET Name=@name WHERE Id=@id', "
            "new SqlParameter('@name', name), new SqlParameter('@id', id))."
        ),
        "frameworks":      ["ef6"],
        "tags":            ["parameterization", "sql", "ef6", "dml"],
    },

    # =========================================================================
    #  SECCIÓN 9: NHibernate — parametrización en ORM legacy
    # =========================================================================

    {
        "id":              "SAN-PARAM-024",
        "rule_type":       "sanitizer",
        "symbol":          "NHibernate.IQuery.SetParameter",
        "name":            "NHibernate IQuery.SetParameter — parametrización de HQL",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.97,
        "limitations": (
            "El HQL (template) debe ser estático — no construir con datos del usuario. "
            "Solo el valor del parámetro puede ser dinámico."
        ),
        "description": (
            "NHibernate IQuery.SetParameter() — parametrización para queries HQL. "
            "session.CreateQuery('from User where Id = :id').SetParameter('id', userId)."
        ),
        "frameworks":      ["generic"],
        "tags":            ["parameterization", "sql", "nhibernate", "hql"],
    },
    {
        "id":              "SAN-PARAM-025",
        "rule_type":       "sanitizer",
        "symbol":          "NHibernate.ISQLQuery.SetParameter",
        "name":            "NHibernate ISQLQuery.SetParameter — parametrización de SQL nativo",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.97,
        "limitations": (
            "Mismas limitaciones que IQuery.SetParameter. "
            "El SQL nativo debe ser estático."
        ),
        "description": (
            "NHibernate ISQLQuery.SetParameter() para SQL nativo parametrizado. "
            "session.CreateSQLQuery('SELECT * WHERE Id = :id').SetParameter('id', userId)."
        ),
        "frameworks":      ["generic"],
        "tags":            ["parameterization", "sql", "nhibernate", "native-sql"],
    },

    # =========================================================================
    #  SECCIÓN 10: NPoco — micro-ORM con parametrización posicional
    # =========================================================================

    {
        "id":              "SAN-PARAM-026",
        "rule_type":       "sanitizer",
        "symbol":          "NPoco.Database.Execute",
        "name":            "NPoco Database.Execute con parámetros posicionales",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["sql_parameter"],
        "confidence":      0.97,
        "limitations": (
            "Usa @0, @1, @2... como placeholders posicionales. "
            "El SQL debe ser estático — los valores van como argumentos adicionales. "
            "db.Execute('DELETE WHERE Id = @0', userId) ← SEGURO."
        ),
        "description": (
            "NPoco Database.Execute() con parámetros posicionales. "
            "Usa @N como placeholders — NPoco los convierte a DbParameter."
        ),
        "frameworks":      ["generic"],
        "tags":            ["parameterization", "sql", "npoco", "positional"],
    },

    # =========================================================================
    #  SECCIÓN 11: DESERIALIZACIÓN SEGURA — type-safe serializers
    #  La parametrización también aplica a deserialización: usar tipos
    #  conocidos y seguros en lugar de tipos arbitrarios.
    # =========================================================================

    {
        "id":              "SAN-PARAM-027",
        "rule_type":       "sanitizer",
        "symbol":          "System.Text.Json.JsonSerializer.Deserialize",
        "name":            "System.Text.Json.JsonSerializer.Deserialize<T> — deserialización type-safe",
        "sanitizes":       ["INSECURE_DESERIALIZATION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["type_safe_deserialization"],
        "confidence":      0.97,
        "limitations": (
            "Confidence 0.97 — System.Text.Json es seguro por defecto. "
            "No soporta TypeNameHandling → no puede deserializar tipos arbitrarios. "
            "EXCEPCIÓN: si se usa con JsonSerializerOptions con TypeInfoResolver "
            "mal configurado puede ser menos seguro. "
            "Para polimorfismo usar [JsonDerivedType] (seguro) "
            "en lugar de TypeNameHandling (inseguro)."
        ),
        "description": (
            "System.Text.Json.JsonSerializer.Deserialize<T>() — el deserializador "
            "JSON seguro por defecto de .NET Core. "
            "A diferencia de Newtonsoft.Json con TypeNameHandling, "
            "System.Text.Json no puede deserializar tipos arbitrarios — "
            "solo deserializa al tipo T especificado en el generic. "
            "El tipo T actúa como whitelist implícita de la estructura esperada."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["parameterization", "json", "deserialization",
                            "type-safe", "system.text.json", "recommended"],
    },
    {
        "id":              "SAN-PARAM-028",
        "rule_type":       "sanitizer",
        "symbol":          "System.Runtime.Serialization.DataContractSerializer.ReadObject",
        "name":            "DataContractSerializer con KnownTypes — deserialización con whitelist",
        "sanitizes":       ["INSECURE_DESERIALIZATION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["type_safe_deserialization"],
        "confidence":      0.88,
        "limitations": (
            "Confidence 0.88 — seguro SOLO cuando: "
            "1. No se usa DataContractResolver con tipos arbitrarios. "
            "2. Los KnownTypes están definidos explícitamente. "
            "3. No se deserializa desde fuentes no confiables con tipos desconocidos. "
            "Si se usa DataContractResolver que resuelve tipos dinámicamente → inseguro."
        ),
        "description": (
            "DataContractSerializer con KnownTypes explícitos — "
            "deserialización segura con whitelist de tipos. "
            "new DataContractSerializer(typeof(MyType), new[] { typeof(SubType1) }) "
            "Solo puede deserializar los tipos explícitamente declarados como conocidos."
        ),
        "frameworks":      ["generic", "wcf", "aspnetcore"],
        "tags":            ["parameterization", "xml", "deserialization",
                            "wcf", "known-types"],
    },
    {
        "id":              "SAN-PARAM-029",
        "rule_type":       "sanitizer",
        "symbol":          "System.Xml.Serialization.XmlSerializer",
        "name":            "XmlSerializer con tipo explícito — deserialización XML type-safe",
        "sanitizes":       ["INSECURE_DESERIALIZATION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["type_safe_deserialization"],
        "confidence":      0.90,
        "limitations": (
            "Confidence 0.90 — el tipo en el constructor actúa como whitelist. "
            "new XmlSerializer(typeof(MyType)) solo deserializa MyType. "
            "ADVERTENCIA: Todavía puede ser vulnerable a XXE si el XmlReader "
            "no tiene DtdProcessing=Prohibit."
        ),
        "description": (
            "XmlSerializer con tipo explícito en el constructor. "
            "El tipo especificado actúa como whitelist de la estructura esperada. "
            "No puede instanciar tipos arbitrarios como BinaryFormatter."
        ),
        "frameworks":      ["generic", "aspnetcore", "wcf"],
        "tags":            ["parameterization", "xml", "deserialization", "type-safe"],
    },
    {
        "id":              "SAN-PARAM-030",
        "rule_type":       "sanitizer",
        "symbol":          "Newtonsoft.Json.JsonConvert.DeserializeObject",
        "name":            "Newtonsoft.Json con TypeNameHandling.None — deserialización segura",
        "sanitizes":       ["INSECURE_DESERIALIZATION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["type_safe_deserialization"],
        "confidence":      0.85,
        "limitations": (
            "Confidence 0.85 — seguro SOLO con TypeNameHandling.None (default). "
            "Si TypeNameHandling != None → es un SINK, no un sanitizador. "
            "Verificar que no hay JsonSerializerSettings con TypeNameHandling != None "
            "en ninguna parte de la cadena de llamadas."
        ),
        "description": (
            "Newtonsoft.Json JsonConvert.DeserializeObject<T>() con "
            "TypeNameHandling.None (default). "
            "Cuando TypeNameHandling = None, Newtonsoft.Json no procesa "
            "el campo '$type' del JSON → no puede instanciar tipos arbitrarios. "
            "El generic <T> actúa como whitelist del tipo esperado."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["parameterization", "json", "deserialization",
                            "newtonsoft", "typenamehandling-none"],
    },

    # =========================================================================
    #  SECCIÓN 12: MessagePack con resolver seguro
    # =========================================================================

    {
        "id":              "SAN-PARAM-031",
        "rule_type":       "sanitizer",
        "symbol":          "MessagePack.MessagePackSerializer.Deserialize",
        "name":            "MessagePack Deserialize con StandardResolver — deserialización segura",
        "sanitizes":       ["INSECURE_DESERIALIZATION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["type_safe_deserialization"],
        "confidence":      0.88,
        "limitations": (
            "Confidence 0.88 — seguro SOLO con StandardResolver o ContractlessStandardResolver. "
            "INSEGURO con TypelessContractlessStandardResolver (permite tipos arbitrarios). "
            "El tipo generic T o el resolver determinan qué tipos pueden deserializarse."
        ),
        "description": (
            "MessagePack.Deserialize<T>() con resolver estándar. "
            "Usando StandardResolver solo puede deserializar tipos "
            "decorados con [MessagePackObject] — whitelist implícita."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["parameterization", "binary", "deserialization",
                            "messagepack", "standard-resolver"],
    },

    # =========================================================================
    #  SECCIÓN 13: Parametrización en comandos del sistema
    #  ProcessStartInfo.ArgumentList es más seguro que Arguments string.
    # =========================================================================

    {
        "id":              "SAN-PARAM-032",
        "rule_type":       "sanitizer",
        "symbol":          "System.Diagnostics.ProcessStartInfo.ArgumentList",
        "name":            "ProcessStartInfo.ArgumentList — separación de argumentos de OS",
        "sanitizes":       ["COMMAND_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["command_argument_list"],
        "confidence":      0.92,
        "limitations": (
            "Confidence 0.92 — ArgumentList separa los argumentos, evitando "
            "la interpretación de metacaracteres de shell. "
            "CONDICIÓN: UseShellExecute DEBE ser false. "
            "Con UseShellExecute=true no hay protección. "
            "No protege si el argumento es el NOMBRE del ejecutable."
        ),
        "description": (
            "ProcessStartInfo.ArgumentList (IList<string>) permite pasar argumentos "
            "como items separados en lugar de un string concatenado. "
            "Cada argumento se pasa directamente al OS sin interpretación de shell. "
            "Ej: psi.ArgumentList.Add(userProvidedArgument) es seguro con "
            "UseShellExecute = false."
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["parameterization", "command", "process",
                            "argument-list", "os"],
    },

    # =========================================================================
    #  SECCIÓN 14: XML — XmlReader con settings seguras como parametrización
    # =========================================================================

    {
        "id":              "SAN-PARAM-033",
        "rule_type":       "sanitizer",
        "symbol":          "System.Xml.XmlReaderSettings",
        "name":            "XmlReaderSettings con DtdProcessing=Prohibit — configuración segura del parser",
        "sanitizes":       ["XXE"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["xml_parser_config"],
        "confidence":      0.98,
        "limitations": (
            "Confidence 0.98 — la configuración es estructuralmente segura. "
            "DEBE incluir: DtdProcessing = DtdProcessing.Prohibit "
            "                Y XmlResolver = null. "
            "Solo DtdProcessing.Prohibit sin XmlResolver=null puede dejar "
            "algunas vías de acceso abiertas en versiones antiguas de .NET."
        ),
        "description": (
            "XmlReaderSettings con DtdProcessing=Prohibit y XmlResolver=null "
            "deshabilita el procesamiento de DTD externas — previene XXE. "
            "Es la 'parametrización' del parser XML: "
            "var settings = new XmlReaderSettings { "
            "    DtdProcessing = DtdProcessing.Prohibit, "
            "    XmlResolver = null "
            "}; "
            "XmlReader.Create(stream, settings)."
        ),
        "frameworks":      ["generic", "aspnetcore", "wcf"],
        "tags":            ["parameterization", "xml", "xxe", "dtd", "parser-config"],
    },
    {
        "id":              "SAN-PARAM-034",
        "rule_type":       "sanitizer",
        "symbol":          "System.Xml.XmlDocument.XmlResolver",
        "name":            "XmlDocument.XmlResolver = null — deshabilitar resolución externa",
        "sanitizes":       ["XXE"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["xml_parser_config"],
        "confidence":      0.95,
        "limitations": (
            "Confidence 0.95 — XmlResolver=null deshabilita la resolución de "
            "entidades externas en XmlDocument. "
            "Debe configurarse ANTES de Load/LoadXml. "
            "No deshabilita completamente el procesamiento DTD — "
            "para máxima seguridad usar XmlReader con DtdProcessing=Prohibit."
        ),
        "description": (
            "Asignar XmlDocument.XmlResolver = null deshabilita la resolución "
            "de entidades externas, previniendo XXE. "
            "xmlDoc.XmlResolver = null; // ANTES de Load() "
            "xmlDoc.Load(stream);"
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["parameterization", "xml", "xxe", "xmlresolver"],
    },

    # =========================================================================
    #  SECCIÓN 15: LDAP — parametrización para Directory Services
    # =========================================================================

    {
        "id":              "SAN-PARAM-035",
        "rule_type":       "sanitizer",
        "symbol":          "System.DirectoryServices.DirectorySearcher",
        "name":            "DirectorySearcher con filtro parametrizado — prevención LDAP Injection",
        "sanitizes":       ["SQL_INJECTION"],
        "sanitizer_type":  "PARAMETERIZATION",
        "encoding_context": ["ldap_filter"],
        "confidence":      0.80,
        "limitations": (
            "Confidence 0.80 — DirectorySearcher no tiene API de parametrización "
            "nativa como SQL. "
            "La 'parametrización' en LDAP se hace mediante encoding de caracteres "
            "especiales LDAP: ( ) * \\ / \\0 se encodan como \\28 \\29 \\2A \\5C \\2F \\00. "
            "No es parametrización estructural — requiere encoding correcto del filtro."
        ),
        "description": (
            "DirectorySearcher usado como mitigación de LDAP Injection "
            "mediante construcción correcta del filtro LDAP. "
            "El filtro debe usar el formato LDAP con values correctamente escapados. "
            "Para encoding correcto usar: "
            "var safeInput = input.Replace('\\\\', '\\\\5C').Replace('*', '\\\\2A') "
            "  .Replace('(', '\\\\28').Replace(')', '\\\\29');"
        ),
        "frameworks":      ["generic", "aspnetcore"],
        "tags":            ["parameterization", "ldap", "directory", "active-directory"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  FUNCIONES DE ACCESO AL CATÁLOGO
# ─────────────────────────────────────────────────────────────────────────────

def get_parameterization_sanitizer_rules() -> list[dict]:
    """Retorna el catálogo completo de sanitizadores de parametrización."""
    return PARAMETERIZATION_SANITIZERS


def get_parameterization_sanitizer_symbols() -> set[str]:
    """Retorna el conjunto de prefijos de símbolo para lookup O(1)."""
    return {rule["symbol"] for rule in PARAMETERIZATION_SANITIZERS}


def get_sanitizers_for_vulnerability(vulnerability: str) -> list[dict]:
    """
    Retorna los sanitizadores de parametrización para un tipo de vulnerabilidad.
    Args:
        vulnerability: e.g. "SQL_INJECTION", "INSECURE_DESERIALIZATION", "XXE"
    """
    return [
        r for r in PARAMETERIZATION_SANITIZERS
        if vulnerability in r.get("sanitizes", [])
    ]


def get_sql_parameterization_sanitizers() -> list[dict]:
    """Retorna todos los sanitizadores de parametrización SQL."""
    return [
        r for r in PARAMETERIZATION_SANITIZERS
        if "SQL_INJECTION" in r.get("sanitizes", [])
    ]


def get_deserialization_safe_alternatives() -> list[dict]:
    """Retorna serializadores seguros como alternativas a los inseguros."""
    return [
        r for r in PARAMETERIZATION_SANITIZERS
        if "INSECURE_DESERIALIZATION" in r.get("sanitizes", [])
    ]


def get_linq_sanitizers() -> list[dict]:
    """Retorna sanitizadores basados en LINQ (máxima confianza para SQL)."""
    return [r for r in PARAMETERIZATION_SANITIZERS if "linq" in r.get("tags", [])]


def get_high_confidence_sanitizers(min_confidence: float = 0.95) -> list[dict]:
    """Retorna sanitizadores con confianza >= min_confidence."""
    return [
        r for r in PARAMETERIZATION_SANITIZERS
        if r.get("confidence", 0.0) >= min_confidence
    ]


def get_sanitizer_confidence_map() -> dict[str, float]:
    """
    Retorna mapa {symbol_prefix: confidence} para el TaintAnalyzer.
    Usado para determinar si el taint debe detenerse completamente.
    """
    return {
        rule["symbol"]: rule.get("confidence", 0.0)
        for rule in PARAMETERIZATION_SANITIZERS
    }


def get_sanitizes_vulnerabilities_map() -> dict[str, list[str]]:
    """
    Retorna mapa {symbol_prefix: [vulnerability_kinds]} para matching
    rápido en el TaintAnalyzer.
    """
    return {
        rule["symbol"]: rule.get("sanitizes", [])
        for rule in PARAMETERIZATION_SANITIZERS
    }