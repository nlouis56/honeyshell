from flask import Flask, render_template_string
import psycopg2
import os

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Honeypot Visualizer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet">

    <style>
      .scroll-box {
        max-height: 320px;
        overflow-y: auto;
      }

      .scroll-box thead th {
        position: sticky;
        top: 0;
        z-index: 1;
      }
    </style>
  </head>
  <body class="p-4 bg-light">
    <div class="container">
      <h1 class="mb-4">Honeypot Visualizer</h1>

        <h2>Total Attempts</h2>
        <div class="alert alert-info">
            <p class="mb-0">The total number of login attempts is <strong>{{ total_attempts }}</strong>.</p>
        </div>
      <h2 class="mt-5">Statistics</h2>
      <div class="alert alert-info">
        <p class="mb-0">These tables display the top IP addresses, usernames, and passwords used in login attempts.</p>
      </div>
      <div class="alert alert-info">

      <h3 class="mt-5">Most recent attempts</h3>
      <div class="scroll-box border rounded">
        <table class="table table-striped table-sm mb-0">
          <thead class="table-dark">
            <tr><th>Time</th><th>IP Address</th><th>User</th><th>Password</th></tr>
          </thead>
          <tbody>
            {% for time, ip, user, password in recent_attempts %}
            <tr><td>{{ time }}</td><td>{{ ip }}</td><td>{{ user }}</td><td>{{ password }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <h3 class="mt-5">Top IP Addresses</h3>
      <div class="scroll-box border rounded">
        <table class="table table-striped table-sm mb-0">
          <thead class="table-dark">
            <tr><th>IP Address</th><th>Attempts</th></tr>
          </thead>
          <tbody>
            {% for ip, count in ip_addresses %}
            <tr><td>{{ ip }}</td><td>{{ count }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <h3 class="mt-5">Top Usernames</h3>
      <div class="scroll-box border rounded">
        <table class="table table-striped table-sm mb-0">
          <thead class="table-dark">
            <tr><th>Username</th><th>Attempts</th></tr>
          </thead>
          <tbody>
            {% for user, count in usernames %}
            <tr><td>{{ user }}</td><td>{{ count }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>

      <h3 class="mt-5">Top Passwords</h3>
      <div class="scroll-box border rounded">
        <table class="table table-striped table-sm mb-0">
          <thead class="table-dark">
            <tr><th>Password</th><th>Attempts</th></tr>
          </thead>
          <tbody>
            {% for pw, count in passwords %}
            <tr><td>{{ pw }}</td><td>{{ count }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </body>
</html>
"""



class HoneypotDatabase:
    """Lightweight wrapper around a Postgres connection used only for reads."""

    def __init__(self):
        self._connect()

    def _connect(self):
        dbname = os.environ.get("DB_NAME", "honeypot")
        user = os.environ.get("DB_USER", "user")
        password = os.environ.get("DB_PASSWORD", "password")
        #host = os.environ.get("DB_HOST", "database")
        host = "database"
        port = int(os.environ.get("DB_PORT", "5432"))

        self.connection = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port,
        )
        self.connection.autocommit = True # read-only so it's okay
        self.cursor = self.connection.cursor()

    # --- Query helpers ---------------------------------------------------- #

    def top_ips(self, limit: int = 10):
        """Return a list of (ip, count) tuples ordered by most hits."""
        self.cursor.execute(
            """
            SELECT ip, COUNT(*) AS hits
            FROM attempts
            GROUP BY ip
            ORDER BY hits DESC
            LIMIT %s;
            """,
            (limit,),
        )
        return self.cursor.fetchall()

    def top_usernames(self, limit: int = 10):
        self.cursor.execute(
            """
            SELECT username, COUNT(*) AS hits
            FROM attempts
            GROUP BY username
            ORDER BY hits DESC
            LIMIT %s;
            """,
            (limit,),
        )
        return self.cursor.fetchall()

    def top_passwords(self, limit: int = 10):
        self.cursor.execute(
            """
            SELECT password, COUNT(*) AS hits
            FROM attempts
            GROUP BY password
            ORDER BY hits DESC
            LIMIT %s;
            """,
            (limit,),
        )
        return self.cursor.fetchall()

    def total_attempts(self):
        """Return the total number of login attempts."""
        self.cursor.execute(
            """
            SELECT COUNT(*) FROM attempts;
            """
        )
        return self.cursor.fetchone()[0]

    def recent_attempts(self, limit: int = 10):
        """Return a list of (time, ip, user, password) tuples ordered by most recent."""
        self.cursor.execute(
            """
            SELECT time, ip, username, password
            FROM attempts
            ORDER BY time DESC
            LIMIT %s;
            """,
            (limit,),
        )
        return self.cursor.fetchall()


# Instantiate a single DB connection that the Flask app will reuse.
db = HoneypotDatabase()

app = Flask(__name__)

@app.route("/")
def index():
    """Render the statistics page."""
    context = {
        "recent_attempts": db.recent_attempts(limit=1000),
        "total_attempts": db.total_attempts(),
        "ip_addresses": db.top_ips(limit=1000),
        "usernames": db.top_usernames(limit=1000),
        "passwords": db.top_passwords(limit=1000),
    }
    return render_template_string(HTML_TEMPLATE, **context)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
