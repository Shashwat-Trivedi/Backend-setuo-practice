// require("dotenv").config({ path: "./env" });

import dotenv from "dotenv";

import connectDB from "./db/index.js";

dotenv.config({
    path: "./env"
});

connectDB();














































// import express from "express"
// const app = express();

// ;( async () => {
//     try {
        
//         await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
//         console.log("he")
//         app.on("error", (error) => {
//             console.error("ERR : ", error) 
//             throw error
//         })

//         app.listen(process.env.PORT, () => {
//             console.log("hello")
//         })

//     } catch (error) {
//         console.error("error : " , error)
//         throw error
//     }
// })()