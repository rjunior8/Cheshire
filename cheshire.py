import os
import sys
from datetime import datetime
import argparse
import sqlite3
from passlib.hash import pbkdf2_sha512
import getpass
import string
import traceback
import random
import inspect


DATABASE_SERVICE = "sqlite3"

if DATABASE_SERVICE == "mysql":
  _S = "%s"
elif DATABASE_SERVICE == "postgresql":
  _S = "%s"
elif DATABASE_SERVICE == "sqlite3":
  _S = "?"

class bcolors:
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'

def _except(line, error, function_name, script_name):
  #function_name = function_name.__name__
  err = f"{bcolors.FAIL}ERROR: {bcolors.ENDC}{error} | ERROR ON LINE: {line} | Function: {function_name} | File: {script_name}"
  traceback_err = f"{bcolors.FAIL}*{bcolors.ENDC} {traceback.format_exception_only(type(error), error)}"
  print(err)
  print(traceback_err)

def what_func():
  return inspect.stack()[1][3]

def check_mysql_table_exists(dbcur, tablename):
  #dbcur = dbcon.cursor()
  dbcur.execute("""
    SELECT COUNT(*)
    FROM information_schema.tables
    WHERE table_name = '{0}'
    """.format(tablename.replace('\'', '\'\'')))
  if dbcur.fetchone()[0] == 1:
    #dbcur.close()
    return True

  #dbcur.close()
  return False

def check_sqlite_table_exists(dbcur, tablename):
  try:
    query = f"SELECT count(*) FROM sqlite_master WHERE type='table' AND name={_S}"
    values = (tablename,)
    dbcur.execute(query, values)
    data = dbcur.fetchone()
    return data[0]
  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)

  return True

eg = f"""
  Usage:

    1º Step - If you don't have gpg installed:

      sudo apt install gnupg

    2º Step - Generate a gpg key:

      gpg --full-generate-key

    3º Step - Generate 'users' table:

      python {__file__} -ut -r gpg_user

    4º Step - Create an user:

      python {__file__} -nu -r gpg_user

    5º Step - Generate your table:

      python {__file__} -r [gpg user] -gt -n [table name]

      NOTE: If you don't specify a table name, a 'default' table will be created or searched.
      
  Examples:

    === Generate tables ===

          python {__file__} -r gpg_user -gt -n my_table

    === Create user ===

          python {__file__} -nu -r gpg_user

    === Add a new platform ===

          python {__file__} -u my_user -r gpg_user -t my_table -ap gmail

          python {__file__} -u my_user -r gpg_user -t my_table -ap gmail -2fa

          python {__file__} -u my_user -r gpg_user -t my_table -ap gmail -2fa -sa

    === Get password ===

          python {__file__} -u my_user -r gpg_user -t my_table -gp gmail

    === Change platform info ===

          python {__file__} -cp -u my_user -r gpg_user -t my_table -pn gmail

          python {__file__} -cp -u my_user -r gpg_user -t my_table -pn gmail -2fa

          python {__file__} -cp -u my_user -r gpg_user -t my_table -pn gmail -2fa -sa

    === Delete a platform ===

          python {__file__} -u my_user -r gpg_user -t my_table -dp gmail

    === Delete an user ===

          python {__file__} -du -r gpg_user -u my_user
"""

ap = argparse.ArgumentParser(prog="Cheshire", description="Passwords Managing", epilog=eg, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("-ut", "--user-table", help="Create 'users' table on database.", action="store_true")
ap.add_argument("-gt", "--generate-table", help="Create table on database.", action="store_true")
ap.add_argument("-cp", "--change-password", help="Change platform password.", action="store_true")
ap.add_argument("-nu", "--new-user", help="Create user.", action="store_true")
ap.add_argument("-2fa", "--2-factor-authentication", help="Store platform with 2-Factor Authentication password.", action="store_true")
ap.add_argument("-sa", "--secret-answer", help="Store platform with secret answer.", action="store_true")
ap.add_argument("-du", "--delete-user", help="Delete an user.", action="store_true")
ap.add_argument("-ap", "--add-platform", help="Add a new platform.")
ap.add_argument("-gp", "--get-password", help="Get platform password.")
ap.add_argument("-dp", "--delete-platform", help="Delete a platform.")
ap.add_argument("-u", "--username", help="Name of your user.")
ap.add_argument("-t", "--tablename", help="Name of your table. If not provided, it'll to search on 'default' table.")
ap.add_argument("-n", "--table-name", help="Name of the new table.")
ap.add_argument("-r", "--gpg-user", help="Name of your gpg user.")
ap.add_argument("-pn", "--platform-name", help="Platform name to change password.")
args = vars(ap.parse_args())

s1 = string.ascii_lowercase + "qztp"
s2 = string.ascii_uppercase + "FYKH"
s3 = string.digits + string.digits + "9276480734"
s4 = "!@#€£$§%&/{([)]=}?«»|*-+.:;,~^"

l1 = list(s1)
l2 = list(s2)
l3 = list(s3)
l4 = list(s4)

def connection():
  c, conn = None, None

  try:
    conn = sqlite3.connect("cheshire.db")
    conn.text_factory = str
    c = conn.cursor()
  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)

  return c, conn

def passwdgen(level):
  generated_passwd = ""

  if level == 4:
    level = 6

  first_ch = random.choices(l1, k=level)
  second_ch = random.choices(l2, k=level)
  third_ch = random.choices(l3, k=level)
  fourth_ch = random.choices(l4, k=level)

  final_list = first_ch + second_ch + third_ch + fourth_ch

  generated_passwd += ','.join(final_list)
  generated_passwd = generated_passwd.replace(',', '')

  return generated_passwd

def gpg_enc(gpg_user):
  os.system(f'gpg -e -r {gpg_user} cheshire.db')
  os.remove('cheshire.db')

def gpg_dec():
  os.system('gpg -d -o cheshire.db cheshire.db.gpg')
  os.remove('cheshire.db.gpg')

def create_user_table(gpg_user):
  try:

    if os.path.isfile("cheshire.db.gpg"):
      gpg_dec()

    c, conn = connection()

    query = "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='users'"
    c.execute(query)
    data = c.fetchone()

    if data[0] == 0:

      query = """
        CREATE TABLE IF NOT EXISTS `users` 
        (`id` INTEGER PRIMARY KEY NOT NULL, 
        `username` VARCHAR(50) UNIQUE, 
        `password` VARCHAR(505))
      """

      c.execute(query)
      conn.commit()

      print(f"{bcolors.OKGREEN}[✓]{bcolors.ENDC} 'users' table was created successfully!")

    elif data[0] == 1:
      print(f"{bcolors.WARNING}[!]{bcolors.ENDC} Table 'users' already exists!")

  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)
  finally:
    try:
      c.close()
      conn.close()
      gpg_enc(gpg_user=gpg_user)
      sys.exit(0)
    except Exception as e:
      sys.exit(2)

def add_user(gpg_user):
  try:

    if os.path.isfile("cheshire.db.gpg"):

      check_l1, check_l2, check_l3, check_l4 = False, False, False, False

      username = input("Username: ")
      new_passwd = getpass.getpass(prompt='Password: ', stream=None)
      confirm_new_passwd = getpass.getpass(prompt='Confirm password: ', stream=None)

      msg = """
        Weak password!
        Min. characters (6)
        Be sure that you have the following requirements:
          Upper and lower cases letters;
          Special characters: !@#€£$§%&/{([)]=}?«»|*-+.:;,~^
      """

      if len(new_passwd) < 6:
        print(f"{bcolors.WARNING}[!]{bcolors.ENDC} WARNING:")
        print(msg)

      else:

        for _a, _b, _c, _d in zip(l1,l2,l3,l4):
          if new_passwd.__contains__(_a):
            check_l1 = True
          if new_passwd.__contains__(_b):
            check_l2 = True
          if new_passwd.__contains__(_c):
            check_l3 = True
          if new_passwd.__contains__(_d):
            check_l4 = True

        if check_l1 and check_l2 and check_l3 and check_l4:

          if new_passwd != confirm_new_passwd:
            print(f"{bcolors.FAIL}[x]{bcolors.ENDC} Wrong password!")

          else:

            gpg_dec()

            c, conn = connection()

            query = f"INSERT INTO `users` (`username`, `password`) VALUES ({_S}, {_S})"
            new_hash = pbkdf2_sha512.using(rounds=12, salt_size=300).hash(new_passwd)
            values = (username, new_hash,)
            c.execute(query, values)

            conn.commit()

            print(f"{bcolors.OKGREEN}[✓]{bcolors.ENDC} User was created successfully!")

        else:
          print(f"{bcolors.WARNING}[!]{bcolors.ENDC} WARNING:")
          print(msg)

    else:
      ap.print_help()

  except sqlite3.IntegrityError:
    print(f"{bcolors.WARNING}[!]{bcolors.ENDC} User already exists!")
  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)
  finally:
    try:
      c.close()
      conn.close()
      gpg_enc(gpg_user=gpg_user)
      sys.exit(0)
    except Exception as e:
      sys.exit(2)

def del_user(user, gpg_user):
  try:

    if os.path.isfile("cheshire.db.gpg"):

      gpg_dec()

      c, conn = connection()

      query = f"SELECT `id`, `password` FROM `users` WHERE `username`={_S}"
      values = (user,)
      c.execute(query, values)
      data = c.fetchone()

      if data:

        _id = data[0]
        _hash = data[1]

        are_you_sure = input(f"{bcolors.WARNING}[!]{bcolors.ENDC} This will to delete all records! Are you sure? [Y/n]")

        if are_you_sure.lower() == 'y':

          password_input = getpass.getpass(prompt=f'Password for {user}: ', stream=None)

          if pbkdf2_sha512.verify(password_input, _hash):

            query = "SELECT name FROM sqlite_master WHERE type='table'"
            c.execute(query)
            data = c.fetchall()

            for table in data:
              tablename = table[0]

              if tablename != "users":

                query = f"DELETE FROM `{tablename}` WHERE `user_id`={_S}"
                values = (_id,)
                c.execute(query, values)

            conn.commit()

            query = f"DELETE FROM `users` WHERE `id`={_S}"
            values = (_id,)
            c.execute(query, values)
          
            conn.commit()

            print(f"{bcolors.OKGREEN}[✓]{bcolors.ENDC} User '{user}' was deleted successfully!")

          else:
            print(f"{bcolors.FAIL}[x]{bcolors.ENDC} Wrong password for '{user}'!")

        elif are_you_sure.lower() == 'n':
          pass

        else:
          pass

      else:
        print(f"{bcolors.FAIL}[x]{bcolors.ENDC} User '{user}' not exists!")

    else:
      ap.print_help()

  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)
  finally:
    try:
      c.close()
      conn.close()
      gpg_enc(gpg_user=gpg_user)
      sys.exit(0)
    except Exception as e:
      sys.exit(2)

def table_gen(gpg_user, tablename="default"):
  try:

    if os.path.isfile("cheshire.db.gpg"):
      gpg_dec()

    c, conn = connection()

    table_exists = check_sqlite_table_exists(dbcur=c, tablename=tablename)

    if not table_exists:

      query = f"""
        CREATE TABLE IF NOT EXISTS `{tablename}` 
        (`id` INTEGER PRIMARY KEY NOT NULL, 
        `platform` VARCHAR(50), 
        `password` VARCHAR(50), 
        `Zfa_password` VARCHAR(50), 
        `secret_answer` VARCHAR(300), 
        `date` VARCHAR(19), 
        `user_id` INTEGER NOT NULL, 
        FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`))
      """

      c.execute(query)
      conn.commit()

      print(f"{bcolors.OKGREEN}[✓]{bcolors.ENDC} Table '{tablename}' was created successfully!")

    else:
      print(f"{bcolors.WARNING}[!]{bcolors.ENDC} Table '{tablename}' already exists!")

  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)
  finally:
    try:
      c.close()
      conn.close()
      gpg_enc(gpg_user=gpg_user)
      sys.exit(0)
    except Exception as e:
      sys.exit(2)

def add_platform(user, gpg_user, platform, Zfa_password, secret_answer, tablename="default"):
  try:

    dn = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    gpg_dec()

    c, conn = connection()

    query = f"SELECT `id`, `password` FROM `users` WHERE `username`={_S}"
    values = (user,)
    c.execute(query, values)
    data = c.fetchone()

    if data:

      user_id = data[0]
      user_passwd = data[1]

      password_input = getpass.getpass(prompt=f'Password for {user}: ', stream=None)

      if pbkdf2_sha512.verify(password_input, user_passwd):

        try:
          level = int(input("Enter password level: [1=low | 2=medium | 3=high | 4=super high] [default=2]: "))
        except ValueError as e:
          level = 2

        if level >= 1 and level <= 4:

          platform_passwd = passwdgen(level=level)

          if Zfa_password:
            try:
              Zfa_password_level = int(input("Enter Two-factor authentication password level: [1=low | 2=medium | 3=high | 4=super high] [default=2]: "))
            except ValueError as e:
              Zfa_password_level = 2
            if Zfa_password_level >= 1 and Zfa_password_level <= 4:
              Zfa_password = passwdgen(level=Zfa_password_level)
          else:
            Zfa_password = ''

          if not secret_answer:
            secret_answer = ''
          else:
            secret_answer = input("Secret answer: ")

          query = f"""
            INSERT INTO `{tablename}` 
            (`platform`, `password`, `Zfa_password`, `secret_answer`, `date`, `user_id`) 
            VALUES 
            ({_S}, {_S}, {_S}, {_S}, {_S}, {_S})
          """
          values = (platform, platform_passwd, Zfa_password, secret_answer, dn, user_id,)
          c.execute(query, values)

          conn.commit()

          print(f"{bcolors.OKGREEN}[✓]{bcolors.ENDC} Platform '{platform}' was added to the table '{tablename}' successfully!")

      else:
        print(f"{bcolors.FAIL}[x]{bcolors.ENDC} Wrong password!")

    else:
      print(f"{bcolors.FAIL}[x]{bcolors.ENDC} User not exists!")

  except sqlite3.OperationalError as e:
    if str(e).__contains__("no such table"):
      print(f"{bcolors.FAIL}[x]{bcolors.ENDC} Table '{tablename}' not exists!")

  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)
  finally:
    try:
      c.close()
      conn.close()
      gpg_enc(gpg_user=gpg_user)
      sys.exit(0)
    except Exception as e:
      sys.exit(2)

def del_platform(user, gpg_user, platform, tablename="default"):
  try:

    gpg_dec()

    c, conn = connection()

    query = f"SELECT `id` FROM `users` WHERE `username`={_S}"
    values = (user,)
    c.execute(query, values)
    data = c.fetchone()

    if data:

      user_id = data[0]

      query = f"DELETE FROM `{tablename}` WHERE `platform`={_S} AND `user_id`={_S}"
      values = (platform, user_id,)
      c.execute(query, values)

      conn.commit()

      affected_rows = c.rowcount

      if affected_rows:
        print(f"{bcolors.OKGREEN}[✓]{bcolors.ENDC} Platform '{platform}' was deleted from table '{tablename}' successfully!")
      else:
        print(f"{bcolors.FAIL}[x]{bcolors.ENDC} Platform '{platform}' not exists!")

    else:
      print(f"{bcolors.FAIL}[x]{bcolors.ENDC} User not exists!")

  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)
  finally:
    try:
      c.close()
      conn.close()
      gpg_enc(gpg_user=gpg_user)
      sys.exit(0)
    except Exception as e:
      sys.exit(2)

def get_passwd(user, gpg_user, platform, tablename="default"):
  try:

    gpg_dec()

    c, conn = connection()

    query = f"SELECT `id` FROM `users` WHERE `username`={_S}"
    values = (user,)
    c.execute(query, values)
    data = c.fetchone()

    if data:

      user_id = data[0]

      query = f"SELECT `password`, `Zfa_password`, `secret_answer`, `date` FROM `{tablename}` WHERE `platform`={_S} AND `user_id`={_S}"
      values = (platform, user_id,)
      c.execute(query, values)
      data = c.fetchone()

      if data:

        password = data[0]
        Zfa_password = data[1]
        secret_answer = data[2]
        old_date = data[3]

        print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} Password: {password}")
        print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} 2fa password: {Zfa_password}")
        print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} Secret answer: {secret_answer}")

        curr_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        d1 = datetime.strptime(old_date, "%Y-%m-%d %H:%M:%S")
        d2 = datetime.strptime(curr_date, "%Y-%m-%d %H:%M:%S")

        days = abs((d2 - d1).days)

        if days > 30:
          print(f"{bcolors.WARNING}[!]{bcolors.ENDC} Password for {platform} is old. Is recommended to change it.")

      else:
        print(f"{bcolors.FAIL}[x]{bcolors.ENDC} Platform '{platform}' not exists!")

    else:
      print(f"{bcolors.FAIL}[x]{bcolors.ENDC} User not exists!")

  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)
  finally:
    try:
      c.close()
      conn.close()
      gpg_enc(gpg_user=gpg_user)
      sys.exit(0)
    except Exception as e:
      sys.exit(2)

def change_platform_passwd(user, gpg_user, platform, Zfa_password, secret_answer, tablename="default"):
  try:

    gpg_dec()

    c, conn = connection()

    query = f"SELECT `id` FROM `users` WHERE `username`={_S}"
    values = (user,)
    c.execute(query, values)
    data = c.fetchone()

    if data:

      user_id = data[0]

      try:
        level = int(input("Enter password level: [1=low | 2=medium | 3=high | 4=super high] [default=2]: "))
      except ValueError as e:
        level = 2

      if level >= 1 and level <= 4:

        new_platform_passwd = passwdgen(level=level)

        if Zfa_password and secret_answer:

          try:
            Zfa_password_level = int(input("Enter Two-factor authentication password level: [1=low | 2=medium | 3=high | 4=super high] [default=2]: "))
          except ValueError as e:
            Zfa_password_level = 2

          if Zfa_password_level >= 1 and Zfa_password_level <= 4:

            new_platform_2fa_passwd = passwdgen(level=Zfa_password_level)

            secret_answer = input("New secret answer: ")

            query = f"""
              UPDATE `{tablename}` 
              SET 
              `password`={_S}, 
              `Zfa_password`={_S}, 
              `secret_answer`={_S} 
              WHERE `platform`={_S} 
              AND 
              `user_id`={_S}
            """

            values = (new_platform_passwd, new_platform_2fa_passwd, secret_answer, platform, user_id,)

        elif Zfa_password and not secret_answer:

          try:
            Zfa_password_level = int(input("Enter Two-factor authentication password level: [1=low | 2=medium | 3=high | 4=super high] [default=2]: "))
          except ValueError as e:
            Zfa_password_level = 2

          if Zfa_password_level >= 1 and Zfa_password_level <= 4:

            new_platform_2fa_passwd = passwdgen(level=Zfa_password_level)

            query = f"""
              UPDATE `{tablename}` 
              SET 
              `password`={_S}, 
              `Zfa_password`={_S}, 
              WHERE `platform`={_S} 
              AND 
              `user_id`={_S}
            """

            values = (new_platform_passwd, new_platform_2fa_passwd, platform, user_id,)

        elif not Zfa_password and secret_answer:

          secret_answer = input("New secret answer: ")

          query = f"""
            UPDATE `{tablename}` 
            SET 
            `password`={_S}, 
            `secret_answer`={_S}, 
            WHERE `platform`={_S} 
            AND 
            `user_id`={_S}
          """

          values = (new_platform_passwd, secret_answer, platform, user_id,)

        else:
          query = f"""
            UPDATE `{tablename}` 
            SET 
            `password`={_S} 
            WHERE `platform`={_S} 
            AND 
            `user_id`={_S}
          """

          values = (new_platform_passwd, platform, user_id,)

        c.execute(query, values)

        affected_rows = c.rowcount

        if not affected_rows:
          print(f"{bcolors.FAIL}[x]{bcolors.ENDC} Platform '{platform}' not exists!")
        else:

          date_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

          query = f"UPDATE `{tablename}` SET `date`={_S} WHERE `platform`={_S} AND `user_id`={_S}"
          values = (date_now, platform, user_id,)
          c.execute(query, values)

          conn.commit()

          print(f"{bcolors.OKGREEN}[✓]{bcolors.ENDC} Info for '{platform}' was changed successfully!")
          print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} New password for '{platform}': {new_platform_passwd}")

          if Zfa_password:
            print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} New 2fa password for '{platform}': {new_platform_2fa_passwd}")

          if secret_answer:
            print(f"{bcolors.OKBLUE}[*]{bcolors.ENDC} New secret answer for '{platform}': {secret_answer}")

    else:
      print(f"{bcolors.FAIL}[x]{bcolors.ENDC} User not exists!")

  except sqlite3.OperationalError as e:
    if str(e).__contains__("no such table"):
      print(f"{bcolors.FAIL}[x]{bcolors.ENDC} Table '{tablename}' not exists!")

  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)
  finally:
    try:
      c.close()
      conn.close()
      gpg_enc(gpg_user=gpg_user)
      sys.exit(0)
    except Exception as e:
      sys.exit(2)

def main():

  try:

    if len(sys.argv) == 1:
      ap.print_help()
      sys.exit(0)

    else:

      if args["user_table"] == True:

        for key in args:
          if key != "user_table" and key != "gpg_user":
            if args[key] == True or (not args[key] is None and args[key] != False):
              ap.print_help()
              sys.exit(0)

        gpg_user = args["gpg_user"]

        create_user_table(gpg_user=gpg_user)

      elif args["new_user"] == True:
        
        for key in args:
          if key != "new_user" and key != "gpg_user":
            if args[key] == True or (not args[key] is None and args[key] != False):
              ap.print_help()
              sys.exit(0)

        gpg_user = args["gpg_user"]

        add_user(gpg_user=gpg_user)

      elif args["generate_table"] == True:
        
        for key in args:
          if key != "generate_table" and key != "table_name" and key != "gpg_user":
            if args[key] == True or (not args[key] is None and args[key] != False):
              ap.print_help()
              sys.exit(0)

        gpg_user = args["gpg_user"]

        if not args["table_name"] is None:
          table_gen(gpg_user=gpg_user, tablename=args["table_name"])
        else:
          table_gen(gpg_user=gpg_user)

      elif not args["add_platform"] is None:
        
        for key in args:
          if key != "add_platform" and key != "2_factor_authentication" and key != "username" and key != "tablename" and key != "gpg_user" \
            and key != "secret_answer":
            if args[key] == True or (not args[key] is None and args[key] != False):
              ap.print_help()
              sys.exit(0)

        user = args["username"]
        gpg_user = args["gpg_user"]
        tablename = args["tablename"]
        platform = args["add_platform"]
        is_2fa = args["2_factor_authentication"]
        secret_answer = args["secret_answer"]

        if user is None or platform is None:
          ap.print_help()
          sys.exit(0)

        else:

          if tablename:
            add_platform(user=user, gpg_user=gpg_user, platform=platform, Zfa_password=is_2fa, secret_answer=secret_answer, tablename=tablename)
          else:
            add_platform(user=user, gpg_user=gpg_user, platform=platform, Zfa_password=is_2fa, secret_answer=secret_answer)

      elif not args["get_password"] is None:

        for key in args:
          if key != "username" and key != "gpg_user" and key != "tablename" and key != "get_password":
            if args[key] == True or (not args[key] is None and args[key] != False):
              ap.print_help()
              sys.exit(0)

        user = args["username"]
        gpg_user = args["gpg_user"]
        tablename = args["tablename"]
        platform = args["get_password"]

        if user is None or platform is None:
          ap.print_help()
          sys.exit(0)

        else:

          if tablename:
            get_passwd(user=user, gpg_user=gpg_user, platform=platform, tablename=tablename)
          else:
            get_passwd(user=user, gpg_user=gpg_user, platform=platform)

      elif not args["delete_platform"] is None:

        for key in args:
          if key != "delete_platform" and key != "username" and key != "tablename" and key != "gpg_user":
            if args[key] == True or (not args[key] is None and args[key] != False):
              ap.print_help()
              sys.exit(0)

        user = args["username"]
        gpg_user = args["gpg_user"]
        tablename = args["tablename"]
        platform = args["delete_platform"]

        if tablename:
          del_platform(user=user, gpg_user=gpg_user, tablename=tablename, platform=platform)
        else:
          del_platform(user=user, gpg_user=gpg_user, platform=platform)

      elif args["change_password"] == True:

        for key in args:
          if key != "change_password" and key != "username" and key != "tablename" and key != "gpg_user" and key != "platform_name" \
            and key != "2_factor_authentication" and key != "secret_answer":
            if args[key] == True or (not args[key] is None and args[key] != False):
              ap.print_help()
              sys.exit(0)

        user = args["username"]
        gpg_user = args["gpg_user"]
        tablename = args["tablename"]
        platform = args["platform_name"]
        is_2fa = args["2_factor_authentication"]
        secret_answer = args["secret_answer"]

        if tablename:
          change_platform_passwd(user=user, gpg_user=gpg_user, platform=platform, Zfa_password=is_2fa, secret_answer=secret_answer, tablename=tablename)
        else:
          change_platform_passwd(user=user, gpg_user=gpg_user, platform=platform, Zfa_password=is_2fa, secret_answer=secret_answer)

      elif args["delete_user"] == True:

        for key in args:
          if key != "delete_user" and key != "username" and key != "gpg_user":
            if args[key] == True or (not args[key] is None and args[key] != False):
              ap.print_help()
              sys.exit(0)

        user = args["username"]
        gpg_user = args["gpg_user"]

        del_user(user=user, gpg_user=gpg_user)

      else:
        ap.print_help()
        sys.exit(0)

  except argparse.ArgumentError as exc:
    print(exc.message, "\n", exc.argument)
  except Exception as e:
    _except(line=sys.exc_info()[-1].tb_lineno, error=e, function_name=what_func(), script_name=__file__)
    sys.exit(2)


if __name__ == "__main__":
  main()