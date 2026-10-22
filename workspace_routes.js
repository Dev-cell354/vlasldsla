
const express = require("express");
const router = express.Router();
const db = require("./database");

router.get("/projects",(req,res)=>{
 const rows=db.prepare(
 "SELECT * FROM projects WHERE user_id=?"
 ).all(req.session.userId || 0);
 res.json(rows);
});

router.post("/projects",(req,res)=>{
 const result=db.prepare(
 "INSERT INTO projects(user_id,name) VALUES(?,?)"
 ).run(req.session.userId || 0, req.body.name);
 res.json({success:true,id:result.lastInsertRowid});
});

router.get("/pinned",(req,res)=>{
 const rows=db.prepare(
 "SELECT * FROM chats WHERE pinned=1 AND user_id=?"
 ).all(req.session.userId || 0);
 res.json(rows);
});

router.post("/chats/pin",(req,res)=>{
 db.prepare(
 "UPDATE chats SET pinned=? WHERE id=?"
 ).run(req.body.pinned?1:0,req.body.id);
 res.json({success:true});
});

router.get("/library",(req,res)=>{
 const rows=db.prepare(
 "SELECT * FROM library WHERE user_id=?"
 ).all(req.session.userId || 0);
 res.json(rows);
});

module.exports=router;
