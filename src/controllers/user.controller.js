import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { uploadOnCloudinary } from '../utils/cloudinary.js';
import { User } from '../models/user.model.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import jwt from 'jsonwebtoken';

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

export { registerUser, loginUser, logoutUser, refreshAccessToken };
