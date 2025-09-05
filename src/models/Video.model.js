import mongoose, {Schema} from "mongoose";
import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";

const videoSchema =new Schema(
    {
        videoFile: {
            type: String, //cloudniary url
            required: true
        },

        thumbnail: {
            type: String, //cloudniary url
            required: true
        },

        title: {
            type: String, 
            required: true
        },

        discription: {
            type: String, //cloudniary url
            required: true
        },

        duration: {
            type: Number,
            required: true
        },

        views: {
            type: Number,
            default: 0
        },

        isPublished: {
            type: Boolean,
            daeault: True
        },

        owner: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        }

    },
    {timestamps: true}
);

videoSchema.plugin(mongooseAggregatePaginate);

export const Video = mongoose.model("Video", videoSchema)