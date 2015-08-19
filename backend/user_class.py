"""
This file contains a class representing a user that can be supplied to the flask_login extension for
session management as well as providing details about that user and his or her permissions.
This file also contains utility functions that depend on the User class.
"""


from flask_login import UserMixin
import database_connection as db_conn
import datetime


class User(UserMixin):
    """
    Next few methods are overridden from UserMixin class to provide other than default values.
    Additional methods have been added to provide user-specific functionality.
    """

    def is_active(self):
        return self.active

    def is_authenticated(self):
        return self.authenticated

    def is_anonymous(self):
        return self.anonymous

    def __init__(self, user_id, udata=None):
        """
        Creates a User object and initializes all properties and attributes.
        :param user_id: A string value for the users's id.
        :param udata: User entered profile information
        :return: A filled User object
        """
        self = User.init_user(self, user_id)

    def update_user(self, fields, values):
        query = "UPDATE users SET "
        for i in range(0, len(fields)):
            query += fields[i] + "=%s"
            if i < len(fields) - 1:
                query += ","
            query += " "
        query += "WHERE id=%s"
        result = db_conn.query_db(query, values + [self.db_id], select=False)
        return result

    @staticmethod
    def init_user(u, user_id):
        """
        Gets a user's information from the database and fills in a User object.
        :param u: Instance of User class to fill
        :param user_id: The user's u_id, a.k.a. email address
        :return: A filled User object
        """
        udata = db_conn.query_db('SELECT * FROM `users` WHERE `userid`=%s', [user_id], one=True)
        if udata is not None:
            u.db_id = udata["id"]
            u.fname = udata["first_name"]
            u.lname = udata["last_name"]
            u.date_joined = udata["date_joined"]
            u.acct_type = udata["acct_type"]

            # http://stackoverflow.com/questions/14291636/what-is-the-proper-way-to-convert-between-mysql-datetime-and-python-timestamp
            # time_format = '%Y-%m-%d %H:%M:%S'
            u.suspended_til = udata["suspended_until"]  # .strftime(time_format)
            now = datetime.datetime.now()
            if udata["suspended_until"] is not None and now < udata["suspended_until"]:
                u.suspended = True
            else:
                u.suspended = False

            if udata["suspended_until"] is not None and udata["suspended_until"] >= datetime.datetime(3000, 1, 1):
                u.banned = True
            else:
                u.banned = False

            u.id = user_id
            u.active = True
            u.authenticated = True
            u.anonymous = True
            u.exists = True
        else:
            u.active = False
            u.authenticated = False
            u.anonymous = False
            u.exists = False
            u.id = None
        return u

    @staticmethod
    def create_new_user(user_data, acct_type=3):
        """
        Adds user data to the database if it can.
        :param user_data: A dictionary that MUST have keys "full_name", "password", and "email"
        :param acct_type: Value specifying type of account. 1=administrator 2=maintenance 3=regular user. Default is 3.
        :return: A dictionary representing database fields for this user. None if an error occurred INSERTING into the
        database.
        """
        first_name_space = user_data["full_name"].find(" ")
        fname = user_data["full_name"][0:first_name_space]
        lname = user_data["full_name"][first_name_space + 1:]
        hpass = encode_password(user_data["password"])
        user_id = user_data["email"]

        query = "INSERT INTO `users` " \
                "(`first_name`, `last_name`, `acct_type`, `userid`, `hpass`)" \
                "VALUES (%s, %s, 100, %s, %s, %s)"
        args = [fname, lname, acct_type, user_id, hpass]
        #print query, args
        result = db_conn.query_db(query, args, select=False)
        #print "Attempted create user: ", result
        return result


    @staticmethod
    def validate_credentials(username, password):
        """
        Takes a password and user name, runs the password through a hash and then compares that hash to the stored hash
        to determine the authenticity of a user.
        :param username: The user_id i.e. email address of the user
        :param password: A string representing the entered password
        :return: A complete instance of the User class if authenticated, None if not authenticated.
        """
        user = db_conn.query_db('SELECT * FROM `users` WHERE `userid`=%s', [username], True)

        #print "Validating: ", username, ":", password
        if user is None:  # not a valid username
            return None

        stored_salted_password = user["hpass"]
        end_salt_pos = stored_salted_password.find('==') + 2
        salt = stored_salted_password[0:end_salt_pos]
        # stored_password = stored_salted_password[end_salt_pos:] # this isnt needed I dont think...

        if stored_salted_password == encode_password(password, salt):
            userid = user["userid"]
            return User(userid, user)
        ''' This is a simple test.
        if username == "Xeno" and password == "cars":
            userid = "testing"
            return User(userid)
        '''
        return None


def admin_only_user_update(user_id, fields, values):
    query = "UPDATE users SET "
    for i in range(0, len(fields)):
        query += fields[i] + "=%s"
        if i < len(fields) - 1:
            query += ","
        query += " "
    query += "WHERE id=%s"
    result = db_conn.query_db(query, values + [user_id], select=False)
    return result

def get_all_users():
    query = "SELECT id, CONCAT(first_name, ' ', last_name) AS name, userid, acct_type, suspended_until FROM users " \
            "ORDER BY date_joined DESC, suspended_until DESC"
    result = db_conn.query_db(query)
    for user in result:
        now = datetime.datetime.now()
        if user["suspended_until"] is not None and user["suspended_until"] >= datetime.datetime(3000, 1, 1):
            user["banned"] = True
        else:
            user["banned"] = False

        if user["suspended_until"] is not None and now < user["suspended_until"]:
            user["suspended"] = True
        else:
            user["suspended"] = False
    return result


def encode_password(password, salt=None):
    """
    This will use an HMAC hash combined with a salt to encrypt the password.
    :param password: Value to be encrypted
    :param salt: None if this is the first time hashing the password, a string if this is being used for an auth check.
    :return: The hashed value of the password in utf-8 encoding.
    """
    import uuid
    import hashlib
    import base64
    if salt is None:
        salt = base64.urlsafe_b64encode(uuid.uuid4().bytes)
    else:
        salt = salt.encode('utf-8')
    t_sha = hashlib.sha512()
    t_sha.update((password + salt.decode('utf-8')).encode('utf-8'))
    hashed_password = base64.urlsafe_b64encode(t_sha.digest())

    # hashed_password)
    return (salt+hashed_password).decode('utf-8')
