const electron = require("electron");
const {format} = require("url");
const {join} = require("path");
const Datastore = require("nedb");
const {existsSync, mkdir, writeFile} = require("fs");
const {createHmac} = require("crypto");
const Cryptr = require('cryptr');

const BUNDLEDIR = join(__dirname, ".bundles");
const userdb = join(BUNDLEDIR, "5s6a6as6565s.md5");
const pmdb = join(BUNDLEDIR, "s5a4d5s4ds5a4d5s.sha256");
const {app, BrowserWindow, Menu, ipcMain} = electron;

const salt_string = 'la57H/++@_-78b'

const sessionDetails = {};

if(!existsSync(BUNDLEDIR)){
    mkdir(BUNDLEDIR, {recursive:true}, function(err){});
    writeFile(userdb, "", (err) => "")
    writeFile(pmdb, "", (err) => "")
}

const user = new Datastore({autoload: true, filename: userdb})
const passwdmanager = new Datastore({autoload: true, filename: pmdb})

user.persistence.compactDatafile()
passwdmanager.persistence.compactDatafile()

let mainWindow;
app.on("ready", function(){
    mainWindow = new BrowserWindow({
        webPreferences: {
            nodeIntegration: true,
        },
        icon: "./logo.ico",
    });
    mainWindow.loadURL(format(join(__dirname, "log-in.html")));
    // mainWindow.maximize()
    // Main menu
    const mainMenu = Menu.buildFromTemplate(mainMenuTemplate);
    Menu.setApplicationMenu(mainMenu);
});

// catch item
ipcMain.on('create-user', function(event, data){
    user.find({username: data.username}, (err, tempdata) => {
        if(tempdata.length == 0){
            const hashed_password = createHmac('sha512', data.password).update(salt_string).digest('hex');
            user.insert({
                name: data.name,
                username: data.username,
                password: hashed_password
            }, (err, output) => {
                event.returnValue = true
            });
        }else {
            event.returnValue = false;
        }
    });
});

ipcMain.on("create-log-in", function (event, data) {
   const hashed_password =  createHmac('sha512', data.password).update(salt_string).digest('hex');
   
   user.find({username: data.username}, (err, tempdata) => {
       if(tempdata.length == 1){
           const usr = tempdata[0];
           if(hashed_password == usr.password){
               sessionDetails["name"] = usr.name;
               sessionDetails["username"] = usr.username.replace(" ", "");
               sessionDetails["password"] = hashed_password;
               event.returnValue = "approveLogin"
           }else {
               event.returnValue = "incorrectPassword";
           }
       }else {
           event.returnValue = "userDoesNotExists";
       }
   });
});

ipcMain.on("verify-login", (event, data) => {
    user.find({username: sessionDetails.username, password: sessionDetails.password}, (err, data)=>{
        if(data.length == 1){
            event.returnValue = {verified: true, name: data[0].name, username: data[0].username};
        }else {
            event.returnValue = {verified: false};
        }
    });
});

ipcMain.on("encrypt-information", (event, data) => {
    const hashed_password =  createHmac('sha512', data.userPassword).update(salt_string).digest('hex');
    if(hashed_password === sessionDetails.password){
        const cryptr = new Cryptr(data.userPassword); 
        const encryptedPassword = cryptr.encrypt(data.websitePassword);
        const encryptedWebUsername = cryptr.encrypt(data.websiteUsername);
        passwdmanager.insert({
            user: sessionDetails.username,
            websiteName: data.websiteName,
            websiteUsername: encryptedWebUsername,
            websitePassword: encryptedPassword,
        });
        event.returnValue = {created: true};
    }else {
        event.returnValue = {created: false};
    }
});

function getAllPasswords(event, temp) {
    const passwords = []
    passwdmanager.find({user: sessionDetails.username}, (err, data) => {
        data = data.reverse()
        for (let i = 0; i < data.length; i++) {
            const passwd = data[i];
            const temp = {}
            temp["id"] = i;
            temp["uid"] = passwd._id;
            temp["webName"] = passwd.websiteName;
            temp["webUsername"] = passwd.websiteUsername;
            temp["webPassword"] = passwd.websitePassword;
            passwords.push(temp)
        }
        event.returnValue = passwords;
    });
}
ipcMain.on("get-all-passwords", getAllPasswords);

ipcMain.on("confirm-delete-login", (event, uid={}) => {
    passwdmanager.findOne(uid, (err, data) => {
        if(data._id === uid._id){
            passwdmanager.remove(uid, {multi: false}, (err, numRemoved) => {
                if(numRemoved > 0){
                    event.returnValue = {deleted: true, webName: data.websiteName}
                }else {
                    event.returnValue = {deleted: false, webName: data.websiteName}
                }
            });
        }
    });
});

ipcMain.on("confirm-reveal-login", (event={}, data={}) => {
    const hashed_password =  createHmac('sha512', data.userPassword).update(salt_string).digest('hex');
    if(hashed_password === sessionDetails.password){
        passwdmanager.findOne({_id: data._id}, (err, userData) => {
            const output = {};
            const cryptr = new Cryptr(data.userPassword);
            output["webName"] = userData.websiteName;
            output["webUsername"] = cryptr.decrypt(userData.websiteUsername);
            output["webPassword"] = cryptr.decrypt(userData.websitePassword);
            output["uid"] = userData._id;
            event.returnValue = {error: "", data: output};
        });
    }else {
        event.returnValue = {error: "passwordError"};
    }
});

ipcMain.on("log-out", (event, data) => {
    if(sessionDetails["name"] != undefined){
        delete sessionDetails["name"];
    }
    if(sessionDetails["username"] != undefined){
        delete sessionDetails["username"];
    }
    if(sessionDetails["password"] != undefined){
        delete sessionDetails["password"];
    }
    event.returnValue = true
})

// main menu template
const mainMenuTemplate = []

if(process.platform == "darwin"){
    mainMenuTemplate.unshift({})
}