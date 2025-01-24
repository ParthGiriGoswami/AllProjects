import customtkinter
from CTkMessagebox import CTkMessagebox
from PIL import Image
import smtplib
import re
import requests
import random
import spacy
import firebase_admin
import pyrebase
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin import db
import datetime
from pytz import timezone
try:
    cred = credentials.Certificate("cred.json")
    firebase_admin.initialize_app(cred,{'databaseURL':"https://projectname.firebaseio.com"})
except:
    pass
finally:
    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+') 
    config = {"apiKey": "your api","authDomain": "domain","databaseURL": "database url","projectId": "id","storageBucket": "enter","messagingSenderId": "enter the info","appId": "enter the info","measurementId": "enter the info"}
    firebase = pyrebase.initialize_app(config)
    auth1 = firebase.auth()
    db1 = firebase.database()
    nlp=spacy.load("en_core_web_sm")
    from chatterbot import ChatBot
    chatbot = ChatBot('AI',logic_adapters=["chatterbot.logic.BestMatch","chatterbot.logic.MathematicalEvaluation","chatterbot.logic.TimeLogicAdapter"])
    customtkinter.set_appearance_mode("Dark")
    customtkinter.set_default_color_theme("blue")
    class passwod(customtkinter.CTkToplevel):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.geometry("700x700+500+50")
            self.title('Forget Password')
            self.resizable(False,False)
            self.forget()
        def forget(self):
            self.info4=customtkinter.CTkLabel(self,text="",width=700)
            self.info4.place(x=0,y=30)
            self.frame1=customtkinter.CTkFrame(self,width=500,height=600)
            self.frame1.place(x=100,y=50)
            self.user1=customtkinter.CTkEntry(self.frame1,placeholder_text="Enter your email id",width=450)
            self.user1.place(x=20,y=20)
            self.info2=customtkinter.CTkLabel(self.frame1,text="",width=500)
            self.info2.place(x=0,y=60)
            self.change=customtkinter.CTkLabel(self.frame1,text="",width=500)
            self.change.place(x=0,y=100)
            self.connection1()
        def on_enter(self,event):
            j=0
            if(self.user1.get().lower().strip().endswith("@gmail.com")=="False"):
                self.info2.configure(text="Please enter valid email id")
            else:
                try:
                    result1 = db.reference("/users").get()
                    for i in result1:
                        if(result1.get(i, {}).get('Email Id')==self.user1.get().strip().lower()):
                            j=1
                            break
                    if (j==1):
                        try:
                            s = smtplib.SMTP("smtp.gmail.com", 587)  
                            s.starttls()
                            s.login("s9174213@gmail.com", "ojwneohzsklvsmbl")
                            self.user1.configure(state="disabled")
                            self.otp = random.randint(1000, 9999)
                            msg="Your otp is "+str(self.otp)
                            s.sendmail("s9174213@gmail.com",self.user1.get().strip().lower(),msg)
                            self.info2.configure(text="An otp is send to this email.")
                            self.change.configure(text="Not your id.                   to change")
                            self.link2 = customtkinter.CTkLabel(self.frame1, text="click here", text_color="dodgerblue",cursor="hand2")
                            self.link2.place(x=230,y=100)
                            my_font = customtkinter.CTkFont(family="times new roman", size=58)
                            self.b1 = customtkinter.CTkEntry(master=self.frame1,width=20,font=my_font)
                            self.b1.place(x=140,y=140)
                            self.b1.bind("<Key>",self.clicker)
                            self.b1.bind("<BackSpace>",self.deleted)
                            self.b2 = customtkinter.CTkEntry(master=self.frame1,width=20,font=my_font,state="disabled")
                            self.b2.place(x=190,y=140)
                            self.b2.bind("<BackSpace>",self.deleted1)
                            self.b2.bind("<Key>",self.clicker1)
                            self.b3 = customtkinter.CTkEntry(master=self.frame1,width=20,font=my_font,state="disabled")
                            self.b3.place(x=240,y=140)
                            self.b3.bind("<BackSpace>",self.deleted2)
                            self.b3.bind("<Key>",self.clicker2)
                            self.b4 = customtkinter.CTkEntry(master=self.frame1,width=20,font=my_font,state="disabled")
                            self.b4.place(x=290,y=140)
                            self.b4.bind("<Key>",self.clicker3)
                            self.b4.bind("<BackSpace>",self.deleted3)
                            self.b4.bind("<Return>",self.sol)
                            self.b1.focus_set()
                        except:
                            self.info2.configure(text="Please check your internet connection")
                            self.user1.configure(state="normal")
                            self.user1.delete(0,"end")
                    else:
                        self.info2.configure(text="Can't find account associated with this id")
                        self.user1.configure(state="normal")
                        self.user1.delete(0,"end")
                except:
                    self.info2.configure(text="Please check your internet connection")
                    self.user1.configure(state="normal")
                    self.user1.delete(0,"end")
        def deleted(self,event):
            self.b1.delete(0,"end")
            self.b1.focus_set()
        def deleted1(self,event):
            self.b2.delete(0,"end")
            self.b2.configure(state="disabled")
            self.b1.configure(state="normal")
            self.b1.focus_set()
        def deleted2(self,event):
            self.b3.delete(0,"end")
            self.b3.configure(state="disabled")
            self.b2.configure(state="normal")
            self.b2.focus_set()
        def deleted3(self,event):
            self.b4.delete(0,"end")
            self.b4.configure(state="disabled")
            self.b3.configure(state="normal")
            self.b3.focus_set()
        def clicker(self,event):
            if(event.char=="0" or event.char=="1" or event.char=="2" or event.char=="3" or event.char=="4" or event.char=="5" or event.char=="6" or event.char=="7" or event.char=="8" or event.char=="9"):
                self.b1.configure(state="normal")
                self.b2.focus_set()
            else:
                self.b1.configure(state="disabled")
        def clicker1(self,event):
            if(event.char=="0" or event.char=="1" or event.char=="2" or event.char=="3" or event.char=="4" or event.char=="5" or event.char=="6" or event.char=="7" or event.char=="8" or event.char=="9"):
                self.b2.configure(state="normal")
                self.b1.configure(state="disabled")
                self.b2.configure(state="normal")
                self.b3.focus_set()
            else:
                self.b2.configure(state="disabled")
        def clicker2(self,event):
            if(event.char=="0" or event.char=="1" or event.char=="2" or event.char=="3" or event.char=="4" or event.char=="5" or event.char=="6" or event.char=="7" or event.char=="8" or event.char=="9"):
                self.b3.configure(state="normal")
                self.b2.configure(state="disabled")
                self.b3.configure(state="normal")
                self.b4.focus_set()
            else:
                self.b3.configure(state="disabled")
        def clicker3(self,event):
            if(event.char=="0" or event.char=="1" or event.char=="2" or event.char=="3" or event.char=="4" or event.char=="5" or event.char=="6" or event.char=="7" or event.char=="8" or event.char=="9"):
                self.b4.configure(state="normal")
                self.b3.configure(state="disabled")
                self.b4.configure(state="normal")
            else:
                self.b4.configure(state="disabled")
        def sol(self,event):
            self.b1.focus_set()
            self.info2=customtkinter.CTkLabel(self.frame1,text="",width=500)
            self.info2.place(x=0,y=210)
            if(str(self.otp)==self.b1.get()+self.b2.get()+self.b3.get()+self.b4.get()):
                self.passwd=customtkinter.CTkEntry(self.frame1,placeholder_text="Enter new password",width=450,show="*")
                self.passwd.place(x=20,y=240)
                self.conpasswd=customtkinter.CTkEntry(self.frame1,placeholder_text="Confirm new password",width=450,show="*")
                self.conpasswd.place(x=20,y=290)
                self.info3=customtkinter.CTkLabel(self.frame1,text="",width=500)
                self.info3.place(x=0,y=320)
                self.v=customtkinter.CTkButton(self.frame1, text="Verify",command=self.verify2,width=50)
                self.v.place(x=40,y=360)
            else:
                self.info2.configure(text="Incorrect otp")
                self.b1.configure(state="normal")
                self.b2.configure(state="normal")
                self.b3.configure(state="normal")
                self.b4.configure(state="normal")
                self.b3.delete(0,"end")
                self.b2.delete(0,"end")
                self.b1.delete(0,"end")
                self.b4.delete(0,"end")
                self.b1.focus_set()
        def verify2(self):
            if(self.passwd.get().strip()=="" or self.conpasswd.get().strip()==""):
                self.info3.configure(text="Fill all fields")
            elif(self.passwd.get().strip()!=self.conpasswd.get().strip()):
                self.info3.configure(text="Password and confirm password must be same")
            else:
                result1 = db.reference("/users").get()
                for i in result1:
                    if(result1.get(i, {}).get('Email Id')==self.user1.get().strip().lower()):
                        user = auth.get_user_by_email(self.user1.get().strip().lower())
                        auth.update_user(user.uid, password=self.passwd.get().strip())
                        data={
                            "Email Id":self.user1.get().lower().strip(),
                            "Password":self.passwd.get().strip()
                            }
                        db1.child("users").child(user.uid).set(data)
                        CTkMessagebox(title="Success", message="Password changed successfully")
                        self.destroy()
        def connection1(self):
              timeout=5
              try:
                  requests.head("http://www.google.com/", timeout=timeout)
                  self.info4.configure(text='The internet connection is active')
                  self.user1.bind("<Return>",self.on_enter)
                  self.user1.configure(state="normal")
                  self.passwd.configure(state="normal")
                  self.conpasswd.configure(state="normal")
                  self.v.configure(state="normal")
              except requests.ConnectionError:
                  self.info4.configure(text="The internet connection is down")
                  self.user1.unbind("<Return>")
                  self.user1.configure(state="disabled")
                  self.passwd.configure(state="disabled")
                  self.conpasswd.configure(state="disabled")
                  self.v.configure(state="disabled")
              self.after(5000, self.connection1)
    class App(customtkinter.CTk):
        def __init__(self):
            super().__init__()
            self.appearance_mode_optionemenu = customtkinter.CTkOptionMenu(self, values=["Dark", "Light"],command=self.change_appearance_mode_event)
            self.appearance_mode_optionemenu.place(x=1380,y=0)
            self.title("Chatbot")
            self.geometry("1523x781+0+0")
            self.resizable(False,False)
            self.login()
        def change_appearance_mode_event(self, new_appearance_mode: str):
            customtkinter.set_appearance_mode(new_appearance_mode)
        def login(self):
            self.frame1=customtkinter.CTkFrame(self,width=500,height=649)
            self.frame1.place(x=530,y=70)
            self.label=customtkinter.CTkLabel(self.frame1,width=500,text="Login",fg_color="Black",text_color="white")
            self.label.place(x=0,y=0)
            img = customtkinter.CTkImage(Image.open("image1.png"),size=(250,250))
            panel =customtkinter.CTkLabel(self.frame1, text="",image = img)
            panel.place(x=125, y=80)
            self.user=customtkinter.CTkEntry(self.frame1,placeholder_text="Email Id",width=450)
            self.user.place(x=20,y=340)
            self.passwd=customtkinter.CTkEntry(self.frame1,placeholder_text="Password",width=450,show="*")
            self.passwd.place(x=20,y=380)
            self.info1=customtkinter.CTkLabel(self.frame1,text="",width=500,text_color=("#8B1A1A","#EE2C2C"))
            self.info1.place(x=0,y=420)
            self.submit=customtkinter.CTkButton(self.frame1, text="Login",command=self.verify)
            self.submit.place(x=60,y=460)
            self.link1 = customtkinter.CTkLabel(self.frame1, text="Forget Password", text_color="dodgerblue")
            self.link1.place(x=310,y=460)
            self.link1.bind("<Button-1>", lambda event: self.forgetpw())
            self.link1.configure(cursor="hand2")
            self.info=customtkinter.CTkLabel(self.frame1,text="Don't have a account")
            self.info.place(x=140,y=505)
            self.link2 = customtkinter.CTkLabel(self.frame1, text="click here", text_color="dodgerblue")
            self.link2.place(x=263,y=505)
            self.info=customtkinter.CTkLabel(self.frame1,text="to sign in")
            self.info.place(x=319,y=505)
            self.info2=customtkinter.CTkLabel(self.frame1,text="",width=500)
            self.info2.place(x=0,y=525)
            self.toplevel_window=None
            self.connection()
        def connection(self):
            timeout=5
            try:
                requests.head("http://www.google.com/", timeout=timeout)
                self.info1.configure(text='The internet connection is active')
                self.link2.bind("<Button-1>", lambda event: self.signin())
                self.link2.configure(cursor="hand2")
                self.user.configure(state="normal")
                self.passwd.configure(state="normal")
                self.submit.configure(state="normal")
            except requests.ConnectionError:
                self.info1.configure(text="The internet connection is down")
                self.link1.configure(cursor="")
                self.link2.configure(cursor="")
                self.link1.unbind("<Button-1>")
                self.link2.unbind("<Button-1>")
                self.user.configure(state="disabled")
                self.passwd.configure(state="disabled")
                self.submit.configure(state="disabled")
            self.after(5000, self.connection)
        def verify(self):
            if(self.user.get().strip()=="" or self.passwd.get().strip()==""):
                self.info2.configure(text="All fields are required")
            elif(not re.fullmatch(regex,self.user.get().strip().lower())):
                self.info2.configure(text="Invalid Email Id")
            elif(self.user.get().strip().lower().find(" ")!=-1):
                self.info2.configure(text="Invalid Email Id")
            else:
                try:
                    try:
                        self.userid=auth1.sign_in_with_email_and_password(self.user.get().strip().lower(),self.passwd.get().strip())
                        self.chatbot1()
                    except:
                        self.info2.configure(text="Incorrect Email Id or Password")    
                except:
                    self.info2.configure(text="Please check your internet connection")
        def signin(self):
            self.frame1=customtkinter.CTkFrame(self,width=500,height=649)
            self.frame1.place(x=530,y=70)
            self.label=customtkinter.CTkLabel(self.frame1,width=500,text="Sign In",fg_color="Black",text_color="white")
            self.label.place(x=0,y=0)
            img = customtkinter.CTkImage(Image.open("image1.png"),size=(250,250))
            panel =customtkinter.CTkLabel(self.frame1, text="",image = img)
            panel.place(x=125, y=30)
            self.info4=customtkinter.CTkLabel(self.frame1,text="",width=500,text_color=("#8B1A1A","#EE2C2C"))
            self.info4.place(x=0,y=290)
            self.user=customtkinter.CTkEntry(self.frame1,placeholder_text="Email Id",width=450)
            self.user.place(x=20,y=330)
            self.passwd=customtkinter.CTkEntry(self.frame1,placeholder_text="Password",width=450,show="*")
            self.passwd.place(x=20,y=370)
            self.info2=customtkinter.CTkLabel(self.frame1,text="",width=500)
            self.info2.place(x=0,y=530)
            self.submit=customtkinter.CTkButton(self.frame1, text="Sign In",command=self.verify1)
            self.submit.place(x=180,y=560)
            self.info=customtkinter.CTkLabel(self.frame1,text="Already have a account")
            self.info.place(x=150,y=590)
            self.link3 = customtkinter.CTkLabel(self.frame1, text="click here", text_color="dodgerblue")
            self.link3.place(x=285,y=590)
            self.connection1()
        def connection1(self):
              timeout=5
              try:
                  requests.head("http://www.google.com/", timeout=timeout)
                  self.info4.configure(text="The internet connection is active")
                  self.link3.bind("<Button-1>", lambda event: self.login())
                  self.link3.configure(cursor="hand2")
                  self.user.configure(state="normal")
                  self.passwd.configure(state="normal")
                  self.submit.configure(state="normal")
              except requests.ConnectionError:
                  self.info4.configure(text="The internet connection is down")
                  self.link3.unbind("<Button-1>")
                  self.link3.configure(cursor="")
                  self.user.configure(state="disabled")
                  self.passwd.configure(state="disabled")
                  self.submit.configure(state="disabled")
              self.after(5000, self.connection1)
        def verify1(self):
            if(self.user.get().strip()=="" or self.passwd.get().strip()==""):
                self.info2.configure(text="All fields are required")
            elif(not re.fullmatch(regex,self.user.get().strip().lower())):
                self.info2.configure(text="Invalid Email Id")
            elif(self.user.get().strip().lower().find(" ")!=-1):
                self.info2.configure(text="Invalid Email Id")
            elif(len(self.passwd.get().strip())<=6):
                self.info2.configure(text="Password should not be less than 6 characters")
            else:
                j=0
                result1 = db.reference("/users").get()
                for i in result1:
                    if(result1.get(i, {}).get('Email Id')==self.user.get().lower().strip()):
                        j=1
                        break
                if (j==0):
                    s = smtplib.SMTP("smtp.gmail.com", 587)  
                    s.starttls()
                    s.login("s9174213@gmail.com", "ojwneohzsklvsmbl")
                    self.otp = random.randint(1000, 9999)
                    msg="Your otp is "+str(self.otp)
                    s.sendmail("s9174213@gmail.com",self.user.get().lower().strip(),msg)
                    self.window=customtkinter.CTkToplevel(self)
                    self.window.geometry("700x400+500+200")
                    self.window.title('OTP')
                    self.window.resizable(False,False)
                    self.info4=customtkinter.CTkLabel(self.window,text="",width=700)
                    self.info4.place(x=0,y=30)
                    self.frame1=customtkinter.CTkFrame(self.window,width=500,height=300)
                    self.frame1.place(x=100,y=50)
                    self.info2=customtkinter.CTkLabel(self.frame1,text="An otp is send to this email.",width=500)
                    self.info2.place(x=0,y=60)
                    my_font = customtkinter.CTkFont(family="times new roman", size=58)
                    self.b1 = customtkinter.CTkEntry(master=self.frame1,width=20,font=my_font)
                    self.b1.place(x=140,y=140)
                    self.b1.bind("<Key>",self.clicker)
                    self.b1.bind("<BackSpace>",self.deleted1)
                    self.b2 = customtkinter.CTkEntry(master=self.frame1,width=20,font=my_font,state="disabled")
                    self.b2.place(x=190,y=140)
                    self.b2.bind("<Key>",self.clicker1)
                    self.b2.bind("<BackSpace>",self.deleted1)
                    self.b3 = customtkinter.CTkEntry(master=self.frame1,width=20,font=my_font,state="disabled")
                    self.b3.place(x=240,y=140)
                    self.b3.bind("<Key>",self.clicker2)
                    self.b3.bind("<BackSpace>",self.deleted2)
                    self.b4 = customtkinter.CTkEntry(master=self.frame1,width=20,font=my_font,state="disabled")
                    self.b4.place(x=290,y=140)
                    self.b4.bind("<Key>",self.clicker3)
                    self.b4.bind("<BackSpace>",self.deleted3)
                    self.b4.bind("<Return>",self.sol)
                    self.b1.focus_set()
                    self.info3=customtkinter.CTkLabel(self.frame1,text="",width=700)
                    self.info3.place(x=0,y=240)
                else:
                    self.info2.configure(text="Already registered")
        def deleted(self,event):
            self.b1.delete(0,"end")
            self.b1.focus_set()
        def deleted1(self,event):
            self.b2.delete(0,"end")
            self.b2.configure(state="disabled")
            self.b1.configure(state="normal")
            self.b1.focus_set()
        def deleted2(self,event):
            self.b3.delete(0,"end")
            self.b3.configure(state="disabled")
            self.b2.configure(state="normal")
            self.b2.focus_set()
        def deleted3(self,event):
            self.b4.delete(0,"end")
            self.b4.configure(state="disabled")
            self.b3.configure(state="normal")
            self.b3.focus_set()
        def clicker(self,event):
            if(event.char=="0" or event.char=="1" or event.char=="2" or event.char=="3" or event.char=="4" or event.char=="5" or event.char=="6" or event.char=="7" or event.char=="8" or event.char=="9"):
                self.b1.configure(state="normal")
                self.b2.focus_set()
            else:
                self.b1.configure(state="disabled")
        def clicker1(self,event):
            if(event.char=="0" or event.char=="1" or event.char=="2" or event.char=="3" or event.char=="4" or event.char=="5" or event.char=="6" or event.char=="7" or event.char=="8" or event.char=="9"):
                self.b2.configure(state="normal")
                self.b1.configure(state="disabled")
                self.b2.configure(state="normal")
                self.b3.focus_set()
            else:
                self.b2.configure(state="disabled")
        def clicker2(self,event):
            if(event.char=="0" or event.char=="1" or event.char=="2" or event.char=="3" or event.char=="4" or event.char=="5" or event.char=="6" or event.char=="7" or event.char=="8" or event.char=="9"):
                self.b3.configure(state="normal")
                self.b2.configure(state="disabled")
                self.b3.configure(state="normal")
                self.b4.focus_set()
            else:
                self.b3.configure(state="disabled")
        def clicker3(self,event):
            if(event.char=="0" or event.char=="1" or event.char=="2" or event.char=="3" or event.char=="4" or event.char=="5" or event.char=="6" or event.char=="7" or event.char=="8" or event.char=="9"):
                self.b4.configure(state="normal")
                self.b3.configure(state="disabled")
                self.b4.configure(state="normal")
            else:
                self.b4.configure(state="disabled")
        def sol(self,event):
            if(str(self.otp)==self.b1.get()+self.b2.get()+self.b3.get()+self.b4.get()):
                try:
                    data={
                        "Email Id":self.user.get().lower().strip(),
                        "Password":self.passwd.get().strip()
                        }
                    auth1.create_user_with_email_and_password(self.user.get().lower().strip(),self.passwd.get().strip())
                    userid = auth1.sign_in_with_email_and_password(self.user.get().lower().strip(),self.passwd.get().strip())
                    db1.child("users").child(userid['localId']).set(data)
                    self.login()
                    self.window.destroy()
                except:
                    pass
            else:
                self.info3.configure(text="Incorrect otp")
                self.b1.configure(state="normal")
                self.b2.configure(state="normal")
                self.b3.configure(state="normal")
                self.b4.configure(state="normal")
                self.b3.delete(0,"end")
                self.b2.delete(0,"end")
                self.b1.delete(0,"end")
                self.b4.delete(0,"end")
                self.b1.focus_set()
        def forgetpw(self):
            self.link1.configure(cursor="")
            self.link1.unbind("<Button-1>")
            if self.toplevel_window is None or not self.toplevel_window.winfo_exists():
                self.toplevel_window = passwod(self)
            else:
                self.toplevel_window.focus()
        def connection2(self):
            timeout=5
            try:
                requests.head("http://www.google.com/", timeout=timeout)
                self.frame2.configure(width=0)
                self.frame2.configure(height=0)
                self.info5.configure(text="")
                self.info5.configure(width=0)
                self.info5.configure(height=0)
                self.send.configure(state='normal')
                self.sendbtn.configure(state='normal')
            except requests.ConnectionError:
                self.frame2.configure(width=1520)
                self.frame2.configure(height=210)
                self.info5.configure(text="Internet connection is not available")
                self.info5.configure(width=1520)
                self.info5.configure(height=210)
                self.send.configure(state='disabled')
                self.sendbtn.configure(state='disabled')
            self.after(5000, self.connection2)
        def chatdet1(self,event):
            if(self.send.get()!=""):
                r=self.send.get()
                new_r=r.replace('+',' + ').replace('-',' - ').replace('*',' * ').replace('/',' / ').replace('^',' ^ ').replace('(',' ( ').replace(')',' ) ').replace('[',' [ ').replace(']',' ] ').replace('{',' { ').replace('{',' { ')
                self.answered=chatbot.get_response(new_r)
                x = datetime.datetime.now(timezone('UTC'))
                data={"Question":r,"Answer":str(self.answered),"Date":x.strftime("%d-%b-%Y"),"Time":x.strftime("%I:%M %p")}
                db1.child('chatdat').child(self.userid['localId']).push(data)
                self.frame1.after(1, self.frame1._parent_canvas.yview_moveto, 100.0)
                self.ai()
        def chatdet(self):
            if(self.send.get()!=""):
                r=self.send.get()
                new_r=r.replace('+',' + ').replace('-',' - ').replace('*',' * ').replace('/',' / ').replace('^',' ^ ').replace('(',' ( ').replace(')',' ) ').replace('[',' [ ').replace(']',' ] ').replace('{',' { ').replace('{',' { ')
                self.answered=chatbot.get_response(new_r)
                x = datetime.datetime.now(timezone('UTC'))
                data={"Question":r,"Answer":str(self.answered),"Date":x.strftime("%d-%b-%Y"),"Time":x.strftime("%I:%M %p")}
                db1.child('chatdat').child(self.userid['localId']).push(data)
                self.frame1.after(1, self.frame1._parent_canvas.yview_moveto, 100.0)
                self.ai()
        def ai(self):
            try:
                self.btn1.configure(state="disabled")
                self.btn2.configure(state="normal")
                self.info.configure(state='disable')
                self.submit5.configure(state='disabled')
                self.reset.configure(state='disabled')
                self.my_font = customtkinter.CTkFont(family="times new roman", size=18)
                self.frame1=customtkinter.CTkScrollableFrame(self,width=1000,height=710)
                self.frame1.place(x=400,y=30)
                self.frame1.columnconfigure(0, weight=0)
                self.frame1.columnconfigure(1, weight=3)
                self.n=1
                data = db1.child('chatdat').child(self.userid['localId']).get()
                x = datetime.datetime.now(timezone('UTC'))
                i = datetime.datetime(1999, 12, 1).strftime("%d-%b-%Y")
                if data.val() is not None:
                    for result in data.val().items():
                        if(result[1]['Date']==x.strftime("%d-%b-%Y") and i!=x.strftime("%d-%b-%Y")):
                            self.date=customtkinter.CTkLabel(self.frame1,text='Today')
                            self.date.grid(row=self.n,column=0,columnspan=2)
                            i=result[1]['Date']
                            self.n+=1
                        elif(result[1]['Date']!=x.strftime("%d-%b-%Y") and i!=x.strftime("%d-%b-%Y") and result[1]['Date']!=i):
                            self.date=customtkinter.CTkLabel(self.frame1,text=result[1]['Date'])
                            self.date.grid(row=self.n,column=0,columnspan=2)
                            i=result[1]['Date']
                            self.n+=1
                        message=result[1]['Question'],"\n",result[1]["Time"]
                        messagetxt = ''.join(message)
                        self.question=customtkinter.CTkLabel(self.frame1,text=messagetxt,font=self.my_font,text_color="white",anchor="e",wraplength=500,justify="left",fg_color="#075E54",corner_radius=10)
                        self.question.grid(row=self.n,column=1,sticky="e",pady=5)
                        response=result[1]['Answer'],"\n",result[1]["Time"]
                        responsetxt = ''.join(response)
                        self.answer=customtkinter.CTkLabel(self.frame1,font=self.my_font,text=responsetxt,anchor="e",text_color="white",wraplength=500,justify="left",fg_color="black",corner_radius=10)
                        self.answer.grid(row=self.n+1,column=0,sticky="w",pady=5)
                        self.n+=2
            except:
                pass
            finally:
                self.send=customtkinter.CTkEntry(self,placeholder_text="Enter message",width=950)
                self.send.bind("<Return>",self.chatdet1)
                self.send.place(x=400,y=750)
                self.sendbtn=customtkinter.CTkButton(self, text="Send",command=self.chatdet,width=50)
                self.sendbtn.place(x=1350,y=750)
                self.send.focus_set()
                self.frame1.after(1, self.frame1._parent_canvas.yview_moveto, 100.0)
                self.frame2=customtkinter.CTkFrame(self,fg_color='black')
                self.frame2.place(x=0,y=300)
                self.my_font1 = customtkinter.CTkFont(family="times new roman", size=80)
                self.info5=customtkinter.CTkLabel(self.frame2,text="",width=0,height=0,font=self.my_font1)
                self.info5.place(x=0,y=0)
                self.connection2()
        def open_toplevel(self):
            self.btn2.configure(state="disabled")
            self.btn1.configure(state="normal")
            self.user5.configure(state='normal')
            self.submit5.configure(state='normal')
            self.reset.configure(state='disabled')
            self.user5.focus_set()
            self.frame1=customtkinter.CTkScrollableFrame(self,width=1000,height=710)
            self.frame1.place(x=400,y=30)
            self.frame2=customtkinter.CTkFrame(self,fg_color='black',width=0,height=0)
            self.frame2.place(x=0,y=300)
            self.my_font1 = customtkinter.CTkFont(family="times new roman", size=80)
            self.info5=customtkinter.CTkLabel(self.frame2,text="",width=0,height=0,font=self.my_font1)
            self.info5.place(x=0,y=0)
            self.send.place_forget()
            self.sendbtn.place_forget()
        def pr1(self,event):
            if(self.send.get()!=""):
                x = datetime.datetime.now(timezone('UTC'))
                data1={"Message":self.send.get(),"Date":x.strftime("%d-%b-%Y"),"Time":x.strftime("%I:%M %p")}
                data2={"Response":self.send.get(),"Date":x.strftime("%d-%b-%Y"),"Time":x.strftime("%I:%M %p")}
                self.send.delete(0,'end')
                db1.child(self.test_str1).child(self.test_str).push(data1)
                db1.child(self.test_str).child(self.test_str1).push(data2)
                self.frame1.after(1, self.frame1._parent_canvas.yview_moveto, 100.0)
                self.verify3()
        def pr(self):
            if(self.send.get()!=""):
                x = datetime.datetime.now(timezone('UTC'))
                data1={"Message":self.send.get(),"Date":x.strftime("%d-%b-%Y"),"Time":x.strftime("%I:%M %p")}
                data2={"Response":self.send.get(),"Date":x.strftime("%d-%b-%Y"),"Time":x.strftime("%I:%M %p")}
                self.send.delete(0,'end')
                db1.child(self.test_str1).child(self.test_str).push(data1)
                db1.child(self.test_str).child(self.test_str1).push(data2)
                self.frame1.after(1, self.frame1._parent_canvas.yview_moveto, 100.0)
                self.verify3()
        def verify3(self):
            if(self.user5.get().strip()==""):
                self.info2.configure(text="All fields are required")
            elif(not re.fullmatch(regex,self.user5.get().strip().lower())):
                self.info2.configure(text="Invalid Email Id")
            elif(self.user5.get().strip().lower().find(" ")!=-1):
                self.info2.configure(text="Invalid Email Id")
            elif(self.user5.get().lower().strip()==self.user.get().strip().lower()):
                self.info2.configure(text="You can't talk with yourself please enter another id")
            else:
                j=0
                self.n=0
                result1 = db.reference("/users").get()
                for i in result1:
                    if(result1.get(i, {}).get('Email Id')==self.user5.get().lower().strip()):
                        j=1
                        break
                if(j==1):
                    try:
                        self.my_font = customtkinter.CTkFont(family="times new roman", size=18)
                        self.test_str = ''.join(letter for letter in self.user5.get().strip().lower() if letter.isalnum())
                        self.test_str1 = ''.join(letter for letter in self.user.get().strip().lower() if letter.isalnum())
                        self.frame1.columnconfigure(0, weight=0)
                        self.frame1.columnconfigure(1, weight=3)
                        data =db1.child(self.test_str1).child(self.test_str).get()
                        i = datetime.datetime(1999, 12, 1).strftime("%d-%b-%Y")
                        x = datetime.datetime.now(timezone('UTC'))
                        if data.val() is not None:
                            for result in data.val().items():
                                if(result[1]['Date']==x.strftime("%d-%b-%Y") and i!=x.strftime("%d-%b-%Y")):
                                    self.date=customtkinter.CTkLabel(self.frame1,text='Today')
                                    self.date.grid(row=self.n,column=0,columnspan=2)
                                    i=result[1]['Date']
                                    self.n+=1
                                elif(result[1]['Date']!=x.strftime("%d-%b-%Y") and i!=x.strftime("%d-%b-%Y") and result[1]['Date']!=i):
                                    self.date=customtkinter.CTkLabel(self.frame1,text=result[1]['Date'])
                                    self.date.grid(row=self.n,column=0,columnspan=2)
                                    i=result[1]['Date']
                                    self.n+=1
                                if 'Message' in result[1].keys():
                                    message=result[1]['Message'],'\n',result[1]['Time']
                                    messagetxt = ''.join(message)
                                    self.message=customtkinter.CTkLabel(self.frame1,text=messagetxt,font=self.my_font,text_color="white",anchor="w",wraplength=500,justify="left",fg_color="#075E54",corner_radius=10)
                                    self.message.grid(row=self.n,column=1,sticky="e",pady=5)
                                elif 'Response' in result[1].keys():
                                    response=result[1]['Response'],"\n",result[1]['Time']
                                    responsetxt = ''.join(response)
                                    self.response=customtkinter.CTkLabel(self.frame1,text=responsetxt,font=self.my_font,text_color="white",anchor="e",wraplength=500,justify="left",fg_color="black",corner_radius=10)
                                    self.response.grid(row=self.n,column=0,sticky="w",pady=5)
                                self.n+=1
                    except:
                        pass
                    finally:
                        self.send=customtkinter.CTkEntry(self,placeholder_text="Enter message",width=950)
                        self.send.bind("<Return>",self.pr1)
                        self.send.place(x=400,y=750)                    
                        self.sendbtn=customtkinter.CTkButton(self, text="Send",command=self.pr,width=50)
                        self.sendbtn.place(x=1350,y=750)
                        self.send.focus_set()
                        self.frame1.after(10, self.frame1._parent_canvas.yview_moveto, 100.0)
                        self.n=0
                        self.submit5.configure(state='disabled')
                        self.user5.configure(state='disabled')
                        self.info2.configure(text="")
                        self.reset.configure(state='normal')
                        self.connection2()
                else:
                    self.info2.configure(text="This email id is not registered in our database")
        def verify2(self):
            self.frame1=customtkinter.CTkScrollableFrame(self,width=1000,height=710)
            self.frame1.place(x=400,y=30)
            self.user5.configure(state='normal')
            self.user5.delete(0,"end")
            self.submit5.configure(state='normal')
            self.reset.configure(state='disabled')
            self.frame2=customtkinter.CTkFrame(self,fg_color='black')
            self.frame2.place(x=0,y=300)
            self.send.place_forget()
            self.sendbtn.place_forget()
            self.my_font1 = customtkinter.CTkFont(family="times new roman", size=80)
            self.info5=customtkinter.CTkLabel(self.frame2,text="",width=0,height=0,font=self.my_font1)
            self.info5.place(x=0,y=0)
            self.connection2()
        def chatbot1(self):
            self.frame1=customtkinter.CTkScrollableFrame(self,width=1000,height=710)
            self.frame1.place(x=400,y=30)
            self.my_font = customtkinter.CTkFont(family="times new roman", size=18)
            self.btn1=customtkinter.CTkButton(self,text="Text with an AI",font=self.my_font,command=self.ai)
            self.btn1.place(x=100,y=330)
            self.btn2=customtkinter.CTkButton(self,text="Talk to a Friend",font=self.my_font,command=self.open_toplevel)
            self.btn2.place(x=100,y=370)
            self.frame1=customtkinter.CTkScrollableFrame(self,width=1000,height=710)
            self.frame1.place(x=400,y=30)
            self.info=customtkinter.CTkLabel(self,text="Enter the username",width=400,anchor='center',state='disabled')
            self.info.place(x=0,y=400)
            self.user5=customtkinter.CTkEntry(self,width=360,state='disabled')
            self.user5.place(x=0,y=440)
            self.submit5=customtkinter.CTkButton(self,text="",width=30,command=self.verify3)
            self.submit5.place(x=360,y=440)
            self.info2=customtkinter.CTkLabel(self,text="",width=400,anchor='center')
            self.info2.place(x=0,y=520)
            self.reset=customtkinter.CTkButton(self,text="Reset",command=self.verify2,state='disabled')
            self.reset.place(x=100,y=480)
    if __name__=="__main__":
        app=App()
        app.mainloop()