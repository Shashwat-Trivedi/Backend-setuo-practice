import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import { User } from '../models/user.model.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import jwt from 'jsonwebtoken';
import { upload } from '../middlewares/multer.middleware.js';

const generateAccessAndRefreshToken = async (userID) => {
    try {
        const user = await User.findById(userID);
        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(
            500,
            'something went wrong while generating access and refresh token'
        );
    }
};

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

    const existingUser = await User.findOne({
        $or: [{ username }, { email }],
    });

    if (existingUser) {
        throw new ApiError(
            409,
            'user already exists with given username or email'
        );
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    const coverImageLocalPath = req.files?.coverImage[0]?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, 'avatar is required');
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, 'avatar file is required');
    }

    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || '',
        username: username.toLowerCase(),
        email,
        password,
    });

    const createdUser = await User.findById(user._id).select(
        '-password -refreshToken'
    );

    if (!createdUser) {
        throw new ApiError(500, 'something went wrong user is not created');
    }

    return res
        .status(201)
        .json(
            new ApiResponse(201, createdUser, 'User Registered Successfully')
        );
});

const loginUser = asyncHandler(async (req, res) => {
    // req body - email/username , password
    // check for email/username exist in db
    // check for matching password
    // generate access and refress token
    // update refress token in db
    // send response to frontend

    console.log(req.body);

    console.log('loginUser content-type:', req.headers['content-type']);
    console.log('loginUser req.body:', req.body);

    const { email, username, password } = req.body;

    if (!username && !email) {
        throw new ApiError(400, 'username or email is required');
    }

    const user = await User.findOne({
        $or: [{ username }, { email }],
    });

    if (!user) {
        throw new ApiError(404, 'user does not exist');
    }

    const isPasswordValid = await user.ispasswordcorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(401, 'password is incorrect');
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
        user._id
    );

    const loggedinUser = await User.findById(user._id).select(
        '-password -refreshToken'
    );

    const option = {
        httpOnly: true,
        secure: true,
    };

    return res
        .status(200)
        .cookie('refreshToken', refreshToken, option)
        .cookie('accessToken', accessToken, option)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedinUser,
                    accessToken,
                    refreshToken,
                },
                'User loogedin successfully'
            )
        );
});

const logoutUser = asyncHandler(async (req, res) => {
    //remove refresh token from db
    // clear all the cookies

    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined,
            },
        },
        {
            new: true,
        }
    );

    const option = {
        httpOnly: true,
        secure: true,
    };

    return res
        .status(200)
        .clearCookie('accessToken', option)
        .clearCookie('refreshToken', option)
        .json(new ApiResponse(200, {}, 'User logged out successfully'));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incommingRefreshToken =
            req.cookies?.refreshToken || req.body?.refreshToken;

        if (!incommingRefreshToken) {
            throw new ApiError(401, 'you are not authorized user');
        }

        const decodedRefreshToken = jwt.verify(
            incommingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        );

        const user = await User.findById(decodedRefreshToken?._id);

        if (!user) {
            throw new ApiError(401, 'Invalid refresh token');
        }

        if (incommingRefreshToken !== user.refreshToken) {
            throw new ApiError(401, 'Refresh token does not match or used');
        }

        const { accessToken, refreshToken: newRefreshToken } =
            await generateAccessAndRefreshToken(user._id);

        const options = {
            httpOnly: true,
            secure: true,
        };

        return res
            .status(200)
            .cookie('accessToken', accessToken, options)
            .cookie('refreshToken', newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    {
                        accessToken: accessToken,
                        refreshToken: newRefreshToken,
                    },
                    'access token refreshed'
                )
            );
    } catch (error) {
        throw new ApiError(401, error?.message || 'Invalid refresh token');
    }
});

const updatePassword = asyncHandler(async (req, res) => {

    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
        throw new ApiError(400, 'old and new password is required' )
    };
    
    const user  =await User.findById(req.user?._id);
    const ispasswordcorrect = await user.ispasswordcorrect(oldPassword);

    if (!ispasswordcorrect) {
        throw new ApiError(400, "invalid old Password")
    }

    user.password = newPassword;
    await user.save({validateBeforeSave: false});

return res.status(200).json(new ApiResponse(200, {} , "password changed successfully"));

});

const getCurrentUser = asyncHandler(async (req, res) => {
    return res.status(200).json(new ApiResponse(200, req.user , 'current user fetched successfully')); 
});

const updateAccountDetails = asyncHandler(async (req, res) => {
    const {fullName , email} = req.body;

    if (!fullName || !email) {
        throw new ApiError(400, "fullName and email are required to change details")
    };

    const user = await User.findByIdAndUpdate(
        req.user._id,
         {
            $set: {
                fullName , email
            }
         },
            { new: true }
    ).select('-password -refreshToken');

        return res.status(200).json(new ApiResponse(200, user , 'User details updated successfully')); 


});

const updateAvatarImage = asyncHandler(async (req , res) => {
    const avatarLocalPath = req.file?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400 , 'avatar image is required');
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);

    if (!avatar) {
        throw new ApiError(500 , 'something went wrong while uploading avatar image');
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: { avatar: avatar.url }
        },
        { new: true }
    ).select('-password -refreshToken');

    return res.status(200).json(
        new ApiResponse(200, user, 'Avatar image updated successfully')
    );

});

const updateCoverImage = asyncHandler(async (req , res) => {
    const coverLocalPath = req.file?.path;

    if (!coverLocalPath) {
        throw new ApiError(400 , 'cover image is required');
    }
    const coverImage = await uploadOnCloudinary(coverLocalPath);

    if (!coverImage) {
        throw new ApiError(500 , 'something went wrong while uploading avatar image');
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: { coverImage: coverImage.url }
        },
        { new: true }
    ).select('-password -refreshToken');

    return res.status(200).json(
        new ApiResponse(200, user, 'Cover image updated successfully')
    );

});

const getUserChannelProfile = asyncHandler(async (req, res ) => {
    const { username } = req.prams;

    if (!username) {
        throw new ApiError(400 , 'username is required');
    }

    const channel = await User.aggregate([
        {
            $match: {
                username : username?.toLowerCase()
            }
        },
        {
            $lookup: {
                from : "subscriptions",
                localField : "_id",
                foreignField : "channel",
                as : "subscribers"
            }
        },
        {
            $lookup: {
                from : "subscriptions",
                localField : "_id",
                foreignField : "subscriber",
                as : "subscribedTo"
            }
        },
        {
            $addFields: {
                subscriberCount : {
                    $size : "$subscribers"
                },
                subscribedToCount : {
                    $size : "$subscribedTo"
                },
                isSubscribed : {
                    $cond : {
                        if : {$in: [ req.user?._id , "$subscribers.subscriber" ]},
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project : {
                fullName : 1,
                username : 1,
                email : 1,
                avatar : 1,
                coverImage : 1,
                subscriberCount : 1,
                subscribedToCount : 1,
                isSubscribed : 1
            }
        }
    ]);

    if (!channel?.length) {
        throw new ApiError(404 , 'channel not found with given username');
    }

    return res.status(200).json(new ApiResponse( 200 , channel[0] , "user channel fetched successfully" ) )
});

export { registerUser, 
    loginUser, 
    logoutUser, 
    refreshAccessToken, 
    updatePassword, 
    getCurrentUser, 
    updateAccountDetails, 
    updateAvatarImage, 
    updateCoverImage,
    getUserChannelProfile };
