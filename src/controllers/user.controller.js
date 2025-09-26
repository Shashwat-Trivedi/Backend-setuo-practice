import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import { User } from '../models/user.model.js'
import { ApiResponse } from '../utils/ApiResponse.js';

const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    // validation of user details - not empty
    // if user already exists - username email
    // check for images , check for avatar
    // upload images to cloudnary , avatar
    //create user object - upload in db
    // remove password and refresh token from response
    // check for user creation
    // send response to frontend

    const { username, email, fullName, password } = req.body;

    if (
        [username, email, fullName, password].some((fields) => {
            fields?.trim() === '';
        })
    ) {
        throw new ApiError(400, 'Given fields are required');
    }

    const existingUser = await  User.findOne({
        $or: [{ username }, { email }]
    })

    if (existingUser) {
        throw new ApiError (409, "user already exists with given username or email")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    if (!avatarLocalPath) {
        throw new ApiError( 400 , 'avatar is required');
    } 

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError( 400 , 'avatar file is required');
    } 

    const user = await User.create({
        fullName , 
        avatar : avatar.url,
        coverImage : coverImage?.url || "",
        username: username.toLowerCase(),
        email,
        password
    })

    const createdUser = await User.findById(user._id).select( "-password -refreshToken" ) 

    if (!createdUser) {
        throw new ApiError(500 , "something went wrong user is not created")
    }

    return res.status(201).json( 
        new ApiResponse(201 , createdUser , "User Registered Successfully")
    )

});

export { registerUser };
