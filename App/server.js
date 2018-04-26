/********************************************
		Einbindung der Abh�ngigkeiten
*********************************************/

//Loading Dependencies for express
var express = require("express");
var formatCurrency = require('format-currency')
var passport = require('passport');
var bCrypt = require('bcrypt-nodejs');
var LocalStrategy = require('passport-local').Strategy;
var expressSession = require('express-session');
var mysql = require('mysql');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var dateFormat = require('dateformat');
var fs = require('fs');


//Loading Dependencies for express
var app = express();
var router = express.Router();
var path = __dirname + '/views';

// Extend filesize limit.
app.use(bodyParser.json({limit: "50mb"}));
app.use(bodyParser.urlencoded({limit: "50mb", extended: true, parameterLimit:50000}));
app.use(cookieParser());

app.use("/",router);

// access-control-origin-header
app.all
(
	'*',
	function (req, res, next)
	{
		res.header("Access-Control-Allow-Origin", "http://localhost:3000");
		res.header("Access-Control-Allow-Headers", "Content-Type");
		res.header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS, DELETE, POST");
		res.header("Access-Control-Allow-Credentials", "true");
		next();
	}
);

// Test connection
//var con = mysql.createConnection({
//  host: "localhost",
//  user: "fa17g17",
//  password: "d795.ze3.K35",
//  database: "fa17g17"
//});

//con.connect(function(err) {
//  if (err) throw err;
//  console.log("Connected!");
//});

/********************************************
						Passport Konfiguration
*********************************************/

//Setze Cookie und initiiere Session auf Serverseite
app.use(expressSession({
	secret: 'fa17g17',
	cookie: {},
	name: 'MPCook',
	resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(id, done) {
	var userName = id.user;
	var selectQuery = "select id, nickname, password, firstname, lastname, role from user where nickname='" + userName + "'";
	con.query(selectQuery, function (err, result) {
		if (err) return done(err);
		var length = result.length;
		if(length == 1){
			return done(null, result[0].nickname);
		} else {
			return done(null, false);
		}
	});
});

passport.use('login', new LocalStrategy({
		usernameField: 'user',
		passwordField: 'password',
    passReqToCallback : true
  },
  function(req, username, password, done) {

		//Prüfe, ob Nutzer vorhanden und Passwort korrekt
		var selectQuery = "select id, nickname, password, firstname, lastname, role from user where nickname='" + req.body.user + "'";
		con.query(selectQuery, function (err, result) {
      if (err) {
				return done(err);
			}
			var length = result.length;
			if(length == 1){
				//Prüfe, ob Passwort-Hashes übereinstimmen
				if (!bCrypt.compareSync(password, result[0].password)){
					return done(null, false, {message:"Username or Password incorrect"});
				} else {
					//Definiere Session Inhalte
					var user = {
						"id":result[0].id,
						"user":req.body.user,
						"firstname":result[0].firstname,
						"lastname":result[0].lastname,
						"role":result[0].role
					};
					//Liefere Session Inhalte an Passport zurück
					return done(null, user);
				}
			} else {
				return done(null, false, {message:"Username or Password incorrect"});
			}
    });
	}));

	passport.use('signup', new LocalStrategy({
			usernameField: 'email',
	    passwordField: 'password',
	    passReqToCallback : true
	  },
	  function(req, username, password, done) {
			var firstName = req.body.firstName;
			var lastName = req.body.lastName;
			var mail = req.body.email;
			var password = req.body.password;
			var passHash = getPasswordHash(password);
			var street = req.body.street;
			var city = req.body.city;
			var postalCode = req.body.postalcode;

			var jsonData = {
				"firstname":firstName,
				"lastname":lastName,
				"mail":mail,
				"password":passHash,
				"street":street,
				"city":city,
				"postalcode":postalCode
			};

			var checkCityQuery = "select * from ort where ortname='" + city + "' and plz='" + postalCode + "'";
			var insertCityQuery = "INSERT INTO ort (ortname, beschreibung, plz) VALUES ('" + city + "','---','" + postalCode + "')";

			con.query(checkCityQuery, function(err, result) {
				var resultID = 0;
				if (err) {
					console.log(err);
					return done(err);
				} else {
					if(result.length == 1) {
						resultID = result[0].id;
						insertUserAfterCallback(resultID, jsonData, done);
					} else {
						console.log("Create a new city");
						con.query(insertCityQuery, function(err, result2) {
							if (err) {
								console.log(err);
								return done(err);
							} else {
								resultID = result2.insertId;
								insertUserAfterCallback(resultID, jsonData, done);
							}
						});
					}
				}
			});
		}
	));

	function insertUserAfterCallback(cityID, userData, done){
		var checkUserQuery = "select id from user where email='" + userData.mail + "'";
	  var insertUserQuery = "INSERT INTO user (nickname, password, firstname, lastname, email, address, ort_id, role)"
	   + "VALUES ('" + userData.mail + "', '" + userData.password + "', '" + userData.firstname + "', '" + userData.lastname + "', '" + userData.mail + "', '"
	   + userData.street + "', " + cityID + ", 2)";

	   console.log(insertUserQuery);
	  	if (cityID != 0) {
	    con.query(checkUserQuery, function(err, result3) {
	      if (err) {
	        console.log(err);
	        return done(err);
	      } else {
	        if (result3.length == 1) {
	          return done(null, false, "User already exists, please specify another mail address");
	        } else {
	          con.query(insertUserQuery, function(err, result4) {
	            if (err) {
	              console.log(err);
	              return done(err);
	            } else {
	              console.log("User Insert at: " + result4.insertId);
	              return done(null, userData.mail, "Successfully created new user: " + userData.mail);
	            }
	          });
	        }
	      }
	    });
	  } else {
	    return done(null, false, "Cannot get city id");
	  }
	}

	function getPasswordHash(password) {
		return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
	}

/********************************************
				URL Zugriff
*********************************************/

//Routes
router.get("/",function(req,res){
	res.sendFile(path + "/index.html");
});

router.get("/about",function(req,res){
	res.sendFile(path + "/about.html");
});

// Login
router.get("/Login",function(req,res){
	res.sendFile(path + "/Login.html");
});

// Registry
router.get("/RegistryPage",function(req,res){
	res.sendFile(path + "/RegistryPage.html");
});

/********************************************
		API - Benutzerverwaltung
*********************************************/
router.post('/user/registration', function(req, res, next){
	passport.authenticate('signup', function(err, user, info){
		if(err) console.log(err);
		if(!user){
			return res.json({created:"false", information:"" + info});
		}
		return res.json({created:"true", info});
	})(req, res, next);
});

router.post('/user/login', function(req, res, next) {
	passport.authenticate('login', function(err, user, info){
		if(err) console.log(err);
		if(!user){
			return res.json({login:"false", information:"" + info.message});
		}
		req.logIn(user, function(err){
			if(err) return next(err);
			//Speichere Nutzer-JSON im lokalen Client-Cache
			res.cookie("UserID",user);
			req.session.user = user;

			var returnValue = "/fa17g17";
			if (req.session.lastURL == null) {
				req.session.lastURL = "/";
				return res.json({login:"true", lastURL:returnValue, UserID:user});
			} else {
				//Wurde der Nutzer zuvor von einer anderen Seite auf den Login verwiesen,
				//so soll dieser auch wieder auf die ursprüngliche Seite weitergeleitet
				//werden.
				returnValue = returnValue.concat(req.session.lastURL);
				req.session.lastURL = null;
				return res.json({login:"true", lastURL:returnValue, UserID:user});
			}
		});
	})(req, res, next);
});

router.get('/user/logout', ensureAuthenticatedREST, function(req, res){
    // Abmeldung vom System
		res.clearCookie("UserID");
		req.logout();
		res.redirect('/index');
});

router.post('/user/update/credentials', ensureAuthenticatedREST, function(req, res){
    // Benutzerdaten aktualisieren
		var userID = req.body.id;
		var mail = req.body.mail;
		var password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null);

		var updateQuery = "update user set email='" + mail + "', nickname='" + mail + "', password='" + password + "' where id=" + userID;
		var checkNewMailQuery = "select id from user where id not like " + userID;
		con.query(checkNewMailQuery, function(err, result) {
			if(err){
				console.log(err);
				res.json({update:"false", message:"Failed to update your account details!!! Please contact the administrator"});
			} else {
				var counter = result.length;
				if(counter == 1){
					res.json({update:"false", message:"The mail address you have specified is already taken. Why don't you stay with your current email address?"});
				} else {
					con.query(updateQuery, function(err, result) {
						if(err) {
							console.log(err);
							res.json({update:"false", message:"Failed to update your account details!!! Please contact the administrator"});
						} else {
							res.json({update:"true", message:"Successfully updated your account details"});
						}
					});
				}
			}
		});
});

router.post('/user/update/contactInfo', ensureAuthenticatedREST, function(req, res){
    // Benutzerdaten aktualisieren
		var userID = req.body.id;
		var firstname = req.body.firstname;
		var lastname = req.body.lastname;
		var telephone = req.body.telephone;
		var street = req.body.street;
		var city = req.body.city;
		var postalcode = req.body.postalcode;

		var checkCityQuery = "Select id from ort where plz ='" + postalcode + "' and ortname='" + city + "'";
		var insertCityQuery = "insert into ort (ortname, beschreibung, plz) values ('" + city + "','---','" + postalcode + "')";

		con.query(checkCityQuery, function (err, result) {
			if(err) {
				console.log(err);
				res.json({update:"false", message:"Failed to update your account details!!! Please contact the administrator"});
			}
			var cLength = result.length;
			var cityID = -1;
			if(cLength == 1){
				cityID = result[0].id;
			} else {
				con.query(insertCityQuery, function(err, result) {
					if(err){
						console.log(err);
						return done(err);
					} else {
						cityID = result.insertId;
					}
				});
			}

			var updateQuery = "update user set firstname ='" + firstname + "', lastname='" + lastname + "', telephone='" + telephone + "', address='" + street + "', ort_id=" + cityID + " where id=" + userID;
			con.query(updateQuery, function(err, result) {
				if(err) {
					console.log(err);
					res.json({update:"false", message:"Failed to update your account details!!! Please contact the administrator"});
				} else {
					res.json({update:"true", message:"Successfully updated your contact details"});
				}
			});
		});
});

router.post('/user/profile', ensureAuthenticatedREST, function(req, res){
    // Weiterleitung auf die Profilseite eines Nutzers
		var userID = req.body.id;
		var userSelectQuery = "select u.*, o.ortname, o.plz from user u inner join ort o on u.ort_id = o.id where u.id =" + userID;
		var wertungSelectQuery = "select b.id, b.beschreibung, w.wert from bewertung b inner join wertung w on b.wertung_id = w.id where b.user_id =" + userID;
		con.query(userSelectQuery, function(err, result) {
			if(err) console.log(err);
			else {
				if(result.length == 1){
					var rating = 0;
					var comment = "No comments available";
					if(result[0].role == 3){
						con.query(wertungSelectQuery, function(err, result2) {
							if (err) {
								console.log(err);
								res.json({success:"false"});
							} else {
								if(result2.length == 1){
									rating = result2[0].wert;
									comment = result2[0].beschreibung;
								}
							}
						});
					}
					var data = {
						"firstname":result[0].firstname,
						"lastname":result[0].lastname,
						"phone":result[0].telephone,
						"mail":result[0].email,
						"street":result[0].address,
						"city":result[0].ortname,
						"postalcode":result[0].plz,
						"rating":rating,
						"comment":comment,
						"role":result[0].role,
						"agency":result[0].agency,
						"agentID":result[0].agent_id
					};
					res.json({success:"true", data});
				} else {
					res.json({success:"false"});
				}
			}
		});
});

router.post('/user/delete', ensureAuthenticatedREST, function(req, res){
    // Löscht das Konto eines Kundens
		var userID = req.body.id;

		//Tabelle Angebot mit on delete cascade auf Immobilie!!!
		//Tabelle Favorit mit on delete cascade auf Angebot!!!
		//Tabelle Kommentar mit on delete cascade auf Angebot!!!
		var deleteImmoQuery = "delete from immobilien where verkaufer_id=" + userID;

		//Tabelle Kontakt mit on delete cascade auf User!!!
		//Tabelle Nachricht mit on delete cascade auf Kontakt!!!
		//Tabelle Bewertung mit on delete cascade auf User!!!
		var deleteUserQuery = "delete from user where id=" + userID;

		con.query(deleteImmoQuery, function(err, result) {
			if (err) {
				console.log(err);
				res.json({deleted:"false"});
			} else {
				con.query(deleteUserQuery, function(err, result2) {
					if (err) {
						console.log(err);
						res.json({deleted:"false"});
					} else {
						res.clearCookie("UserID");
						req.logout();
						res.json({deleted:"true"});
					}
				});
			}
		});
});

 /********************************************
 			Zugriffssicherung für Requests
 *********************************************/

 function ensureAuthenticatedREST(req, res, next) {

   if (req.isAuthenticated()) {
 		return next();
 	} else if (req.headers["app-header"]) {
 	    return next();
 	}
	res.json({accessed:"false", message:"You cannot access the REST call without authentication!!!"});
 }

 function ensureAuthenticatedSITE(req, res, next) {

   if (req.isAuthenticated()) {
 		return next();
 	} else {
		req.session.lastURL = req.url;
 	  res.redirect('/fa17g17/Login');
 	}
 }

/********************************************
		Zugriff auf statische Dateien
*********************************************/


//Zugriff auf Bild-Dateien
app.use('/img', express.static(path + '/img'));

//Zugriff auf CSS-Dateien
app.use('/css', express.static(path + '/css'));

//Zugriff auf Script-Dateien
app.use('/js', express.static(path + '/js'));

//Zugriff Revealjs-Dependencies
app.use('/lib', express.static(path + '/lib'));
app.use('/plugin', express.static(path + '/plugin'));

app.use("*",function(req,res){
  res.sendFile(path + "/404.html");
});

/********************************************
			Server Konfiguration
			Autor: Max Finsterbusch 100%
*********************************************/

var server = app.listen(3000, '127.0.0.1', function(){
	var host = server.address().address
	var port = server.address().port

	console.log("Server is listening at http://%s:%s", host, port)
});
