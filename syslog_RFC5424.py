#!/usr/bin/env python3
#-----------------
#RFC 5424:HEADER:
#-----------------
#PRI  -  represents the Facility and Severity of the message. It's a calculated value: Facility * 8 + Severity
#VERSION  -  Version number of the syslog protocol standard. Currently this can only be 1.
#ISOTIMESTAMP  -  The time when the message was generated in the ISO 8601 format (yyyy-mm-ddThh:mm:ss+-ZONE eg.2020-07-22 14:13:18.604537)
#HOSTNAME  -  The machine that originally sent the message.
#APPLICATION  -  The device or application that generated the message
#PID  -  The process name or process ID of the application that sent the message.
#MESSAGEID  -  The ID number of the message.

#STRUCTURED-DATA - This provides a mechanism to express information in a well-defined and interpretable data format as per RFC 5424. 
#>>STRUCTURED-DATA can contain zero, one, or multiple SD elements. In case of zero structured data elements, the STRUCTURED-DATA field uses NILVALUE. 
#MSG - It contains a free-form message that provides information about the event. 


#This script take a log file and output a .txt in JSON format. For test 't.txt' file for quick result. 
#kern.log file is the actual file, if you want check the actual big log.
#After running the script, do delete the output file, kern_json.txt if you want to rerun the script as it will append to the same file.
 

import json
import re
import dateutil.parser #parsing datetime

def message_cleanup(message): #Clean the message part
    message[-1]=message[-1].rstrip("\n") #removes the '\n' from the last element
    message=' '.join(message)
    return message

def date_time_convert(log_date): #convert datetime to iso8601 formate, eg.2020-07-22 14:13:18.604537
    #Convert to datetime object
    some_datetime_obj = dateutil.parser.parse(log_date)

    #Get date and time and  convert to iso format
    date_extract=some_datetime_obj.date()
    time=(some_datetime_obj.time())
    iso_date_time = str(date_extract) + "T" + str(time)
    return iso_date_time

def json_format(datetime,hostname,appname,message,peer_no,peer_ip): #format into JSON : Serialisation
    #data dictionary
    
    data = {
    'PRI': '<134>',         #PRI  -  represents the Facility and Severity of the message. It's a calculated value: Facility * 8 + Severity    ##For this: [(local0)16 * 8 + 6(Informational)] = 16*8+6 = 134
    'TIMESTAMP':datetime,   #ISO 8601 format (yyyy-mm-ddThh:mm:ss+-ZONE eg.2020-07-22 14:13:18.604537)
    'HOSTNAME':peer_ip,
    'APPLICATION':appname,
    'PID': 'NILVALUE',      #The NILVALUE might be used when a process ID is not available.
    'MESSAGEID': 'NILVALUE',#The NILVALUE is used when the Syslog application does not, or cannot, provide any value. 
    'STRUCTURED-DATA': 'NILVALUE', #In case of zero structured data elements, the STRUCTURED-DATA field uses NILVALUE.
    'MESSAGE':message       #It contains a free-form message that provides information about the event.
    
    #'Peer No':peer_no #this is field is not required for RFC 5424, HOWEVER, it can be used for future for identification of the users(Alex).
    }
    #Notes: APPLICATION, PID, MESSAGEID and STRUCTURED-DATA can be NULL, that is represented by the dash character "-". 
    #The MSG part can be entirely empty (eg. only SDATA is sent).
    #https://support.oneidentity.com/kb/264126/syslog-message-formats

    json_obj = json.dumps(data, indent=4)
    #print(json_obj) #json dumps() convert dict into JSON obj.
    print(json_obj) #test ----------------------------------------------->
    return json_obj



filename=open('kern.log') #open txt in read-only mode, default mode.

counting=1 
while True:
    each_line = filename.readline() #read each line using readline(). There is '\n' at the end.
    if each_line != "": 
        each_element=each_line.split(' ') #splits each line into elements seperated by spaces
        if each_element[6] == 'wireguard:': #Grabs only the wireguard logs

            datetime = each_element[0] + " " + each_element[1] + " " + each_element[2]
            hostname = each_element[3]
            appname = each_element[6].rstrip(':') #removes the ':' char
            message = each_element[8:] #Gets the message part : '['Failed', 'to', 'give', 'packet', 'to', 'userspace', 'from', 'peer', '296', '(90.253.165.83:51722)\n']'      
    
            message=message_cleanup(message) #Remove the unwanted eg '[' and '\n'
            #print(message) ####joint message, eg.'Failed to give packet to userspace from peer 296 (90.253.165.83:51722)'            

            if re.search(r'^Keypair', message): #search for 'Keypair' in the message and if found, will skip parsing that line. 
                ####SKIPPED FOR THE TIME BEING. IN FUTURE MIGHT NEED FOR PEER NO.####
                continue  #'Keypair 136090 destroyed for peer 264' 

            peer_ip_port=re.search(r'peer\s(\d{3})\s\S(\d+.\d+.\d+.\d+):(\d+)', each_line) #'\b' = any character except for new line #search peer no, IP and Port (until the end of line,'')
            if peer_ip_port: #if expression found
                
                peer_no = peer_ip_port.group(1)
                peer_ip = peer_ip_port.group(2)
                ip_port = peer_ip_port.group(3) #if require, can be used
                                
            elif re.search(r'peer\s(\d{3}$)', each_line): #search where line with only peer no. ##expression without IP and port
                
                print('Message: ' +each_line)
                peer_no=re.search(r'peer\s(\d{3}$)', each_line)#search where line with only peer no.               

                peer_no = peer_no.group(1)
                peer_ip = 'NILVALUE' #no IP no found'
            
            elif re.search(r'Invalid', each_line): #search where line with only peer no. ##expression IP only. 
                #Message:Invalid handshake response from 109.201.133.24:3000
                
                invalid_handshake_ip = re.search(r'(\d+.\d+.\d+.\d+):(\d+)', each_line) #get the IP(1) and port(2)         
                peer_ip = invalid_handshake_ip.group(1)
                peer_no = 'NILVALUE' #no peer no found

            print(f'No: {counting}')

            datetime_iso = date_time_convert(datetime) #convert the log datetime to iso 8601 date format
            
            #JSON FORMAT
            json_obj = json_format(datetime_iso,hostname,appname,message,peer_no,peer_ip) #for JSON format
            json_obj = json_obj + '\n' #new line after end of  '}'
            
            with open('kern_json.txt', 'a') as outfile: # Writing to kern_json.txt, append
                outfile.writelines(json_obj)

            counting += 1 #Counting the logs
    else:
        break #end loop once reached to the end of file.
filename.close()




