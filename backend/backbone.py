from flask import Flask
import configuration

import certificate_utils
import werkzeug.serving
werkzeug.serving.BaseWSGIServer.verify_request = certificate_utils.verify_request

app = Flask(__name__, template_folder='templates')


@app.route("/")
def hello():
    import database_connection as db_conn
    query = "select name from sqlite_master where type=\'table\'"
    result = db_conn.query_db(query, [])
    print result
    return "Hello World!<br/>" + certificate_utils.get_user_certificate_str()


if __name__ == "__main__":
    app.run(host='localhost', port=configuration.CYBER_PORT, debug=configuration.CYBER_DEBUG_MODE,
            ssl_context=certificate_utils.context)
