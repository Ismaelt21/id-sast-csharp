// =============================================================
// SAMPLE: Business-like order lookup service
// VULNERABILITY: SQL_INJECTION
// SOURCE: OrderRequestDto.OrderId
// SINK: SqlCommand
// =============================================================

using System;
using System.Data;
using System.Text;
using Microsoft.Data.SqlClient;

namespace Tests.Samples.ThesisCase
{
    public sealed class OrderService
    {
        private readonly string _connectionString;

        public OrderService(string connectionString)
        {
            _connectionString = connectionString;
        }

        public OrderSummaryDto? LoadOrder(OrderRequestDto request)
        {
            var normalized = PrepareOrderKey(request);
            var sql = new OrderSqlBuilder().Build(normalized, request.CustomerSegment);
            return ExecuteLookup(sql);
        }

        private string PrepareOrderKey(OrderRequestDto request)
        {
            var key = request.OrderId;
            if (!string.IsNullOrWhiteSpace(request.CorrelationId))
            {
                key = request.CorrelationId + "-" + key;
            }

            key = ThesisUtilities.NormalizeToken(key);
            if (key.Length > 64)
            {
                key = key.Substring(0, 64);
            }

            return key;
        }

        private OrderSummaryDto? ExecuteLookup(string sql)
        {
            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand(sql, connection);

            connection.Open();
            using var reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
            if (!reader.Read())
            {
                return null;
            }

            return new OrderSummaryDto
            {
                OrderNumber = Convert.ToString(reader["OrderNumber"]) ?? string.Empty,
                CustomerName = Convert.ToString(reader["CustomerName"]) ?? string.Empty,
                TotalAmount = Convert.ToDecimal(reader["TotalAmount"]),
                Status = Convert.ToString(reader["Status"]) ?? string.Empty
            };
        }

        private sealed class OrderSqlBuilder
        {
            public string Build(string orderId, string segment)
            {
                var baseSelect = new StringBuilder();
                baseSelect.Append("SELECT TOP 1 o.OrderNumber, c.DisplayName AS CustomerName, ");
                baseSelect.Append("o.TotalAmount, o.Status ");
                baseSelect.Append("FROM Orders o ");
                baseSelect.Append("INNER JOIN Customers c ON c.Id = o.CustomerId ");

                var whereClause = BuildWhereClause(orderId, segment);
                var orderClause = " ORDER BY o.CreatedAt DESC";
                var sql = baseSelect.ToString() + whereClause + orderClause;

                if (segment.IndexOf("vip", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    sql = sql + " OPTION (RECOMPILE)";
                }

                return sql;
            }

            private string BuildWhereClause(string orderId, string segment)
            {
                var current = "WHERE o.OrderNumber = '" + orderId + "'";
                if (!string.IsNullOrWhiteSpace(segment))
                {
                    var normalizedSegment = ThesisUtilities.NormalizeToken(segment);
                    current = current + " AND c.Segment = '" + normalizedSegment + "'";
                }

                if (current.Length > 32)
                {
                    current = current.Replace("  ", " ");
                }

                return current;
            }
        }
    }
}
