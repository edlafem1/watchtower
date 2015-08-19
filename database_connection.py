"""
This file contains functions used to connect to the database and execute queries in a uniform manner.
"""

from flask import g
#  import mysql.connector as mariadb
import sqlite3 as mariadb
import configuration
from backbone import app


def connect_db():
    """
    Connects to the specific database.
    :return: A MySQLConnection object
    """
    con = mariadb.connect(**configuration.database)
    return con


def get_db():
    """
    Opens a new database connection if there is none yet for the
    current application context.
    :return: The context specific database connection
    """
    if not hasattr(g, 'mariadb'):
        g.mariadb = connect_db()
    return g.mariadb


@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'mariadb'):
        g.mariadb.close()


def query_db(query, args=(), one=False, select=True):
    """
    Use this for all database querying. See example below for how to use.
    To pass variable parts to the SQL statement, use C string formatting(like %s %d)
    in the statement and pass in the arguments as a list. Never directly add them to the SQL statement with string
    formatting.

    user = query_db('select * from users where username = %s',
                [the_username], one=True)
    if user is None:
        print 'No such user'
    else:
        print the_username, 'has the id', user['user_id']

    This example shows how to call the function with parameters in the query itself and only get one result.
    The example below shows a more general example:

    result = query_db('select * from users')
    for user in result:
        print user['username'], 'has the id', user['user_id']

    :param query: The SQL query to be executed
    :param args: A list or tuple of args to be used with the query
    :param one: Boolean representing if a single entry is to be returned or not. Default to False
    :param select: Boolean representing if this is a SELECT statement, or other statement(data modification/insertion)
    :return: If one==False, returns list of dictionaries each representing a row returned; if one==True just a single
    dictionary; if select=False, it will return the row that was last created or modified; None if no results found.
    """
    #  cursor = get_db().cursor(dictionary=True)
    cursor = get_db().cursor()
    cursor.execute(query, args)
    #  if select and cursor.with_rows:
    if select:
        rv = cursor.fetchall()
    else:
        get_db().commit()
        rv = cursor.lastrowid
    cursor.close()
    return (rv[0] if rv else None) if one else rv