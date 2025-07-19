import mysql.connector

# Connect to the same database
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Iam2sickforthis",
    database="netflix_db"
)
cursor = db.cursor()

def search_user(keyword):
    query = "SELECT username FROM users WHERE username LIKE %s"
    cursor.execute(query, ('%' + keyword + '%',))
    results = cursor.fetchall()

    if results:
        print("Search Results:")
        for row in results:
            print(f"- {row[0]}")
    else:
        print("No users found with that keyword.")

if __name__ == "__main__":
    keyword = input("Enter username keyword to search: ")
    search_user(keyword)
