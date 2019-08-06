import time
import random
import datetime
import telepot
import MySQLdb
import os
from prettytable import PrettyTable
from telepot.loop import MessageLoop

db = MySQLdb.connect(host="192.168.0.108", user="root", passwd="secret", db="librenms")
cursor = db.cursor()
sql_command = """ SELECT * FROM services """   
cursor = db.cursor()
sql_command2 = """ SELECT * FROM devices """
cursor = db.cursor()
sql_command3 = """SELECT * FROM alert_updown"""

def handle(msg):
                    chat_id = msg['chat']['id']
                    command = msg['text']

                    if command == '/about':
                        bot.sendMessage(chat_id, "I'm tired")
                    elif command == '/random':
                        bot.sendMessage(chat_id, random.randint(0,9))
                    elif command == '/time':
                        bot.sendMessage(chat_id, str(datetime.datetime.now()))
                    elif command == '/status_realtime':
                        import subprocess
                        rest = subprocess.check_output("mencoba_alerts1.py", shell=True)
                        # rest = os.system('open_alerts.py')
                        rest = str(rest).replace("\\r\\n", "\n")
                        #rest = str(rest)
                        #rest = "\n".join(str(rest).replace("\\r\\n", " "))
                        bot.sendMessage(chat_id, rest)
                    elif command == '/service':
                        cursor.execute(sql_command)
                        for result in cursor.fetchall():
                            bot.sendMessage(chat_id, str("Device ID : ")+str(result[1])+str(", ")+str("Service ID : ")+str(result[2])+str(", ")+str("Service Type : ")+str(result[3]))
                    elif command == '/devices':
                        cursor.execute(sql_command2)
                        for result in cursor.fetchall():
                            bot.sendMessage(chat_id, str("Device ID : ")+str(result[0])+str(", ")+str("Device/Hostname : ")+str(result[1])+str(", ")+str("SysName : ")+str(result[2]))
                    elif command == '/status_week':
                        cursor.execute(sql_command3)
                         for result in cursor.fetchall():
                             bot.sendMessage(chat_id, str("Device ID : ")+str(result[0])+str(", ")+str("Device/Hostname : ")+str(result[1])+str(", ")+str("SysName : ")+str(result[2]))
                    
# Token of bot account
TOKEN = "897901114:AAHMZjnYLHBMrFF-ClDVNYa_YphgXBtlofw"
bot = telepot.Bot(TOKEN)
bot.message_loop(handle)
print ('Bot Ready!')

while 1: 
           time.sleep(10)
