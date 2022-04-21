using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace JWTAuthSecuredAPI.Migrations
{
    public partial class AddedDefaultRoles : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "6ad3bd49-8435-477d-8508-b63fdaa11789");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "bf630ce1-68b9-4e2e-8939-e55e263b92ee");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "c92b223b-91b7-49d4-a3bd-77e1f493358a", "cdb7913f-42a6-416f-ac0b-c849239203ac", "reader", "reader" },
                    { "df068f7d-02ab-4c78-ab5e-78423c9522e6", "7ce902b3-5560-44ad-8ff5-5cd021855231", "admin", "admin" }
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "c92b223b-91b7-49d4-a3bd-77e1f493358a");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "df068f7d-02ab-4c78-ab5e-78423c9522e6");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "6ad3bd49-8435-477d-8508-b63fdaa11789", "94bf22f8-3582-4343-bf6a-d7cd7d86e344", "reader", "" },
                    { "bf630ce1-68b9-4e2e-8939-e55e263b92ee", "e2c52bca-6183-4a45-a6d9-51be5f0c1db9", "admin", "" }
                });
        }
    }
}
