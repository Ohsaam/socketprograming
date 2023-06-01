from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from textwrap import wrap
import socket
import tqdm
import os
import random as rnd
from twilio.rest import Client
from virustotal_python import Virustotal
from pprint import pprint
import hashlib

def Signup():

        global top_s
        top_s=Toplevel()
        top_s.title("회원가입 창")
        top_s.geometry("1199x600+100+50")

        canvas_s = Canvas(top_s, height=500, width=400)
        canvas_s.pack(fill="both", expand=True)
        canvas_s.create_image(0, 0, image=bg_signup, anchor="nw")

        Frame_signup = Frame(top_s, bg="white")
        Frame_signup.place(x=250, y=50, height=420, width=700)

        title = Label(Frame_signup, text="회원가입하기", font=("Segoe Script", 32, "bold"), fg="#5eabf7",bg="white").place(x=200, y=10)

        signup_name = Label(Frame_signup, text="이름", font=("PMingLiU-ExtB", 15, "bold"), fg="#4d647a", bg="white").place(x=60,y=80)
        global txt_name
        txt_name = Entry(Frame_signup, font=("Times new roman", 12), bg="lightgray")
        txt_name.place(x=60, y=110, width=250, height=30)
        signup_user = Label(Frame_signup, text="ID", font=("PMingLiU-ExtB", 15, "bold"), fg="#4d647a", bg="white").place(x=400, y=80)
        global txt_user
        txt_user= Entry(Frame_signup, font=("Times new roman", 12), bg="lightgray")
        txt_user.place(x=400, y=110, width=250, height=30)
        signup_email = Label(Frame_signup, text="메일 주소", font=("PMingLiU-ExtB", 15, "bold"), fg="#4d647a",bg="white").place(x=60, y=150)
        global txt_email
        txt_email= Entry(Frame_signup, font=("Times new roman", 12), bg="lightgray")
        txt_email.place(x=60, y=180, width=250, height=30)
        signup_phoneno = Label(Frame_signup, text="휴대폰 번호", font=("PMingLiU-ExtB", 15, "bold"), fg="#4d647a",bg="white").place(x=400, y=150)
        global txt_phoneno
        txt_phoneno= Entry(Frame_signup, font=("Times new roman", 12), bg="lightgray")
        txt_phoneno.place(x=400, y=180, width=250, height=30)
        signup_pass = Label(Frame_signup, text="비밀번호", font=("PMingLiU-ExtB", 15, "bold"), fg="#4d647a", bg="white").place(x=60, y=220)
        global txt_pass
        txt_pass= Entry(Frame_signup, font=("Times new roman", 12), bg="lightgray",show='*')
        txt_pass.place(x=60, y=250, width=250, height=30)
        signup_confirmpass = Label(Frame_signup, text="비밀번호 확인", font=("PMingLiU-ExtB", 15, "bold"), fg="#4d647a",bg="white").place(x=400, y=220)
        global txt_confirmpass
        txt_confirmpass= Entry(Frame_signup, font=("Times new roman", 12), bg="lightgray",show='*')
        txt_confirmpass.place(x=400, y=250, width=250, height=30)
        signup_question = Label(Frame_signup, text="비밀번호 확인 질문을 선택해 주세요.", font=("PMingLiU-ExtB", 15, "bold"), fg="#4d647a",bg="white").place(x=60, y=290)
        options = [
            "당신의 출생지는?",
            "제일 좋아하는 색은?",
            "첫 담임선생님의 성함은?",
            "가장 좋아하는 음식은?"
        ]

        clicked = StringVar()

        def show():
            global txt_question
            txt_question=clicked.get()

        clicked.set("질문을 선택해 주세요.")
        signup_drop = OptionMenu(Frame_signup, clicked, *options)
        signup_drop.config(font=("Arial", 10, "bold"), fg="#3b3d40", bg="light grey", cursor="hand2")
        signup_drop.place(x=60, y=320, width=210, height=30)
        select_button = Button(Frame_signup, text="Select", command=show, fg="black", bg="light grey").place(x=270,y=320,width=40,height=28)
        signup_answer = Label(Frame_signup, text="정답", font=("PMingLiU-ExtB", 15, "bold"), fg="#4d647a", bg="white").place(x=400, y=290)
        global txt_answer
        txt_answer = Entry(Frame_signup, font=("Times new roman", 12), bg="lightgray")
        txt_answer.place(x=400, y=320, width=250, height=30)
        Signup_btn = Button(top_s, command=signup_function, cursor="hand2", text="회원가입", fg="white",bg="#5eabf7", font=("Book Antiqua", 20)).place(x=510, y=450, width=180, height=40)
        d_button = Button(top_s, text="<- 뒤로가기", command=top_s.destroy, cursor="hand2", fg="white", bg="#5eabf7",font=("Book Antiqua", 10)).place(x=20, y=20, width=80, height=30)


def signup_function():
    if txt_pass.get() == "" or txt_user.get() == "" or txt_name.get() == "" or txt_email.get() == "" or txt_phoneno.get() == "" or txt_confirmpass.get() == "" or txt_answer.get() == "":
        messagebox.showerror("Error", "모든 항목에 값을 입력해 주세요.", parent=top_s)
    elif txt_pass.get() != txt_confirmpass.get():
        messagebox.showerror("Error", "비밀번호가 일치하지 않습니다.", parent=top_s)
    else:
        messagebox.showinfo("Welcome", "회원가입을 성공적으로 완료했습니다.", parent=top_s)

        text_file = open("data.txt", 'a')
        text_file.write(txt_name.get().ljust(30))  #왼쪽으로 30만큼 정렬. 나머지는 빈칸
        text_file.write(txt_user.get().ljust(30))
        text_file.write(txt_email.get().ljust(30))
        text_file.write(txt_phoneno.get().ljust(30))
        text_file.write(txt_pass.get().ljust(30))
        text_file.write(txt_question.ljust(35))
        text_file.write(txt_answer.get().ljust(30) + "\n")
        text_file.close()

        top_s.destroy()
        Login()


def Login():

    global top
    top=Toplevel()
    top.title("로그인")
    top.geometry("1199x600+100+50")

    # Background Image

    #bg = PhotoImage(file="image/login.png")
    #bg_image = Label(top, image=bg).place(x=0, y=0, relwidth=1, relheight=1) 이건 이미지 설정인듯..

    canvas = Canvas(top, height=500, width=400)
    canvas.pack(fill="both",expand=True)
    canvas.create_image(0,0,image=bg_login,anchor="nw")

    #my_label=Label(top,image=photo).pack()
    #bg_button=Button(top,image=bg_login)

    # 로그인 위젯
    Frame_login = Frame(top, bg="white")
    Frame_login.place(x=150, y=150, height=340, width=430)

    title = Label(Frame_login, text="로그인하기", font=("Segoe Script", 35, "bold"), fg="#53a2bd",bg="white").place(x=80, y=30)

    # ID
    login_user = Label(Frame_login, text="ID", font=("PMingLiU-ExtB", 15, "bold"), fg="grey", bg="white").place(x=40,y=120)
    global txt_user
    txt_user = Entry(Frame_login, font=("Times new roman", 12), bg="lightgray") #entry는 입력받는 기입창
    txt_user.place(x=40, y=150, width=350, height=30)

    # 비밀번호
    login_pass = Label(Frame_login, text="비밀번호", font=("PMingLiU-ExtB", 15, "bold"), fg="grey", bg="white").place(x=40,y=190)
    global txt_pass
    txt_pass = Entry(Frame_login, font=("Times new roman", 12), bg="lightgray",show='*') 
    txt_pass.place(x=40, y=220, width=350, height=30)

    # 비밀번호 잊어버림
    forget_btn = Button(Frame_login, text="비밀번호를 잊으셨나요?", command=otp_page,cursor="hand2", bg="white", fg="#53a2bd", bd=0,font=("times new roman", 12)).place(x=40, y=260)

    # 로그인 버튼
    Login_btn = Button(top, command=login_function, cursor="hand2", text="Login", fg="white",bg="#53a2bd", font=("Book Antiqua", 18)).place(x=300, y=470,width=140,height=40)

    # 취소 버튼
    d_button = Button(top, text="<- 뒤로가기", command=top.destroy,cursor="hand2",fg="white",bg="#53a2bd", font=("Book Antiqua", 10)).place(x=20, y=20, width=80, height=30)

def login_function():
    # 텍스트 파일에서 데이터 읽어오기

    get_user=[]
    get_pass=[]
    text_file = open("data.txt", 'r')
    l=text_file.readlines()[1:] #한줄씩 다루기
    for i in l:
        user_details_line=i.rstrip("\n") #줄 맨 오른쪽에서 개행 제거
        each_field=wrap(user_details_line,30) #30만큼 자르고 반환
        get_user.append(each_field[1]) #ID get_user에 저장
        get_pass.append(each_field[4]) #비밀번호 get_pass에 저장
    cred = {get_user[i]: get_pass[i] for i in range(len(get_user))}  # 딕셔너리형태로 저장
    text_file.close()


    if txt_pass.get() == "" or txt_user.get() == "":
        messagebox.showerror("Error", "모든 항목에 값을 입력해 주세요.", parent=top) #하나가 공란일 때 오류

    #elif self.txt_pass.get() !=  or self.txt_user.get() != "Harsh":
    elif txt_pass.get() in cred.values() or txt_user.get() in cred.keys(): #
        if cred[txt_user.get()]==txt_pass.get():
            #messagebox.showinfo("Welcome", "You have successfully logged in", parent=top)
            Transfer()
            #Continue
            #Continue_btn = Button(top, command=Transfer, cursor="hand2", text="Continue", fg="white", bg="#53a2bd",font=("Book Antiqua", 18)).place(x=300, y=470, width=140, height=40)
        else:
            messagebox.showerror("Error", "유효하지 않은 ID/비밀번호입니다.", parent=top)

    else:
        #self.txt_pass.get() not in cred.values() or self.txt_user.get() not in cred.keys():
        messagebox.showerror("Error", "유효하지 않은 ID/비밀번호입니다.", parent=top)






#여기까지

def otp_page():

    global top_o
    top_o = Toplevel()
    top_o.title("Verification Window")
    top_o.geometry("1199x600+100+50")

    # Background Image
    canvas = Canvas(top_o, height=500, width=400)
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, image=bg_login, anchor="nw")


    # OTP widget
    Frame_otp = Frame(top_o, bg="white")
    Frame_otp.place(x=150, y=100, height=440, width=430)

    title = Label(Frame_otp, text="Verify OTP", font=("Segoe Script", 35, "bold"), fg="#53a2bd", bg="white").place(x=80, y=30)

    # Username
    otp_user = Label(Frame_otp, text="Username", font=("PMingLiU-ExtB", 15, "bold"), fg="grey", bg="white").place(x=40, y=120)
    global otp_getuser
    otp_getuser = Entry(Frame_otp, font=("Times new roman", 12), bg="lightgray")
    otp_getuser.place(x=40, y=150, width=350, height=30)

    # Phone number
    otp_phoneno = Label(Frame_otp, text="Phone number", font=("PMingLiU-ExtB", 15, "bold"), fg="grey", bg="white").place(x=40, y=190)
    global otp_getphoneno
    otp_getphoneno = Entry(Frame_otp, font=("Times new roman", 12), bg="lightgray")
    otp_getphoneno.place(x=40, y=220, width=220, height=30)

    # OTP
    otp = Label(Frame_otp, text="OTP", font=("PMingLiU-ExtB", 15, "bold"), fg="grey", bg="white").place(x=40,y=260)
    global otp_get
    otp_get = Entry(Frame_otp, font=("Times new roman", 12), bg="lightgray")
    otp_get.place(x=40, y=290, width=350, height=30)

    Send_btn = Button(top_o, command=otp_generated, cursor="hand2", text="Send OTP", fg="white", bg="#53a2bd",font=("Book Antiqua", 12)).place(x=440, y=315, width=100, height=40)

    Confirm_btn = Button(top_o, command=otp_function,cursor="hand2", text="Confirm", fg="white", bg="#53a2bd",font=("Book Antiqua", 18)).place(x=300, y=470, width=140, height=40)

    d_button = Button(top_o, text="<- Go Back", command=top_o.destroy, cursor="hand2", fg="white", bg="#53a2bd",font=("Book Antiqua", 10)).place(x=20, y=20, width=80, height=30)

def otp_generated():
    global otp
    otp = rnd.randint(100000, 999999)
    account_sid = 'ACd351592ec2c7ea3472603bd81618f1d2'
    auth_token = '84572bee501bcbe8f08b66d1a4f2c729'
    client = Client(account_sid, auth_token)

    message = client.messages \
        .create(
        body='Otp generated for changing password - ' + str(otp),
        from_='+13527024673',
        to='+918696268455'
    )

def otp_function():
    if otp_getuser.get()=='' or otp_getphoneno.get()=='':
        messagebox.showerror("Error", "All fields are required", parent=top_o)
    elif otp==int(otp_get.get()):
        ChangePass()
    else:
        messagebox.showinfo("Error", "Invalid OTP", parent=top_o)













def ChangePass():

    global top_c
    top_c = Toplevel()
    top_c.title("New Password Window")
    top_c.geometry("1199x600+100+50")
    canvas = Canvas(top_c, height=500, width=400)
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, image=bg_login, anchor="nw")


    Frame_pass = Frame(top_c, bg="white")
    Frame_pass.place(x=150, y=100, height=340, width=430)

    title = Label(Frame_pass, text="Change Password", font=("Segoe Script", 25, "bold"), fg="#53a2bd", bg="white").place(x=60, y=30)

    new_pass = Label(Frame_pass, text="New Password", font=("PMingLiU-ExtB", 15, "bold"), fg="grey", bg="white").place(x=40, y=120)
    global new_getpass
    new_getpass = Entry(Frame_pass, font=("Times new roman", 12), bg="lightgray")
    new_getpass.place(x=40, y=150, width=350, height=30)

    new_confirmpass = Label(Frame_pass, text="Confirm Password", font=("PMingLiU-ExtB", 15, "bold"), fg="grey", bg="white").place(x=40, y=190)
    new_getconfirmpass = Entry(Frame_pass, font=("Times new roman", 12), bg="lightgray")
    new_getconfirmpass.place(x=40, y=220, width=350, height=30)

    Send_btn = Button(top_c, command=NewPass_function, cursor="hand2", text="Change Password", fg="white", bg="#53a2bd",font=("Book Antiqua", 12)).place(x=295, y=380, width=150, height=40)

    d_button = Button(top_c, text="<- Go Back", command=top_c.destroy, cursor="hand2", fg="white", bg="#53a2bd",font=("Book Antiqua", 10)).place(x=20, y=20, width=80, height=30)

def NewPass_function():
    get_user = []
    get_pass = []
    text_file = open("data.txt", 'r')
    l = text_file.readlines()[1:]
    for i in l:
        user_details_line = i.rstrip("\n")
        each_field = wrap(user_details_line, 30)
        get_user.append(each_field[1])
        get_pass.append(each_field[4])

    cred = {get_user[i]: get_pass[i] for i in range(len(get_user))}
    print(cred[otp_getuser.get()])
    print(new_getpass.get())
    text_file.close()

    new_file_content = ""
    text_file1 = open("data.txt", 'r')
    m = text_file1.readlines()[0:]
    for i in m:
        user_details_line = i.rstrip("\n")
        new_line = user_details_line.replace(cred[otp_getuser.get()], new_getpass.get()).ljust(30)
        new_file_content += new_line + "\n"
    text_file1.close()

    writing_file = open("data.txt", "w")
    writing_file.write(new_file_content)
    writing_file.close()


def Transfer():

    global top_t
    top_t=Toplevel()
    top_t.title("File Transfer Window")
    top_t.geometry("1199x600+100+50")

    # Background Image
    canvas = Canvas(top_t, height=500, width=400)
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, image=bg_login, anchor="nw")

    # Login widget
    Frame_transfer = Frame(top_t, bg="white")
    Frame_transfer.place(x=50, y=150, height=400, width=530)

    def file_opener():
        global file_input
        file_input = filedialog.askopenfilename(initialdir="/")
        file_label = Label(top_t, text=file_input, font=("PMingLiU-ExtB", 12, "bold"), fg="grey", bg="white").place(x=70, y=210)


    # Select file button
    Select_btn = Button(top_t, command=file_opener, cursor="hand2", text="Select file", fg="white", bg="#53a2bd",font=("Book Antiqua", 18)).place(x=370, y=200, width=140, height=40)

    # Send file button
    Send_btn = Button(top_t, command=client,cursor="hand2", text="Send file", fg="white", bg="#53a2bd",font=("Book Antiqua", 18)).place(x=250, y=290, width=140, height=40)

    title = Label(top_t, text="------------or------------", font=("Segoe Script", 20, "bold"), fg="#53a2bd",bg="white").place(x=100, y=370)

    # Recieve file button
    Recieve_btn = Button(top_t, command=server,cursor="hand2", text="Receive file", fg="white", bg="#53a2bd",font=("Book Antiqua", 18)).place(x=250, y=450, width=140, height=40)

    # Destroy button
    d_button = Button(top_t, text="Logout", command=top_t.destroy, cursor="hand2", fg="white", bg="#53a2bd",font=("Book Antiqua", 10)).place(x=20, y=20, width=80, height=30)

    # Report button
    r_button = Button(top_t, text="Generate Report", command=VirusTotal, cursor="hand2", fg="white", bg="#53a2bd",font=("Book Antiqua", 10)).place(x=1000, y=20, width=150, height=30)

def server():
    global SERVER_HOST
    SERVER_HOST = "172.30.1.69"
    SERVER_PORT = 5001
    # receive 4096 bytes each time
    BUFFER_SIZE = 4096
    SEPARATOR = "<SEPARATOR>"
    # create the server socket
    # TCP socket
    s = socket.socket()
    # bind the socket to our local address
    s.bind((SERVER_HOST, SERVER_PORT))
    # enabling our server to accept connections
    # 5 here is the number of unaccepted connections that
    # the system will allow before refusing new connections
    s.listen(5)
    print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")
    # accept connection if there is any
    client_socket, address = s.accept()
    # if below code is executed, that means the sender is connected
    print(f"[+] {address} is connected.")
    # receive the file infos
    # receive using client socket, not server socket
    received = client_socket.recv(BUFFER_SIZE).decode()
    filename, filesize = received.split(SEPARATOR)
    # remove absolute path if there is
    filename = os.path.basename(filename)
    # convert to integer
    filesize = int(filesize)
    # start receiving the file from the socket
    # and writing to the file stream
    progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "wb") as f:
        while True:
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            f.write(bytes_read)
            progress.update(len(bytes_read))

    client_socket.close()
    s.close()













def client():
    SEPARATOR = "<SEPARATOR>"
    BUFFER_SIZE = 4096  # send 4096 bytes each time step
    # the ip address or hostname of the server, the receiver
    global host
    host = "172.30.1.69"
    # the port, let's use 5001
    port = 5001
    # the name of file we want to send, make sure it exists
    filename = file_input
    # get the file size
    filesize = os.path.getsize(filename)
    # create the client socket
    s = socket.socket()
    print(f"[+] Connecting to {host}:{port}")
    s.connect((host, port))
    print("[+] Connected.")
    # send the filename and filesize
    s.send(f"{filename}{SEPARATOR}{filesize}".encode())
    # start sending the file
    progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "rb") as f:
        while True:
            # read the bytes from the file
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                # file transmitting is done
                break
            # we use sendall to assure transimission in
            # busy networks
            s.sendall(bytes_read)
            # update the progress bar
            progress.update(len(bytes_read))
    # close the socket
    s.close()

    # Storing Data in file
    SERVER_HOST = "172.30.1.69"
    text_file = open("iphistory.txt", 'a')
    text_file.write(txt_user.get().ljust(30))
    text_file.write(SERVER_HOST.ljust(30))
    text_file.write(host.ljust(30))
    text_file.write(file_input.ljust(30) + "\n")
    text_file.close()

def VirusTotal():
    vtotal = Virustotal(API_KEY="ab8230be5cf403599b78f8ca37f76e7cc1074f8fe23104e1b5914e7994921530", API_VERSION="v3")
    FILE_PATH = file_input
    files = {"file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))}
    resp = vtotal.request("files", files=files, method="POST")

    pprint(resp.data)

    filename = file_input
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        print(sha256_hash.hexdigest())

    FILE_ID = sha256_hash.hexdigest()
    resp1 = vtotal.request(f"files/{FILE_ID}")
    pprint(resp1.data)

root=Tk()
# Background Image
bg = PhotoImage(file="image/001.png")
bg_login = PhotoImage(file="image/002.png")
bg_signup = PhotoImage(file="image/003.png")
bg_image = Label(root, image=bg).place(x=0, y=0, relwidth=1, relheight=1)

# Welcome widget

#title = Label(root, text="Welcome!!!", font=("Copperplate Gothic Bold", 32, "bold"), fg="#0b0c17",bg="light yellow").place(x=450, y=50)

# Signup button
Signup_btn = Button(root,cursor="hand2",command=Signup,text="Signup", fg="white", bg="#8fc7b5",font=("Book Antiqua", 18)).place(x=125, y=275, width=140, height=40)

# Login button
Login_btn = Button(root, cursor="hand2", command=Login, text="Login", fg="white", bg="#8fc7b5",font=("Book Antiqua", 18)).place(x=125, y=200, width=140, height=40)


root.title("Welcome Window")
root.geometry("1199x600+100+50")
root.resizable(False, False)
root.mainloop()