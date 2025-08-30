// require("dotenv").config({ path: "./env" });
// import dotenv from "dotenv";
// dotenv.config({
    //     path: "./env"
    // });
    // import express from "express"
    import connectDB from "./db/index.js";
    import { app } from "./app.js";
    
    
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



connectDB()
.then(() => {
    app.listen(process.env.PORT, () => {
        console.log(`Server is listening to port ${process.env.PORT}`)
    })
})
.catch((error) => {
    console.error("Database connection error:", error);
})