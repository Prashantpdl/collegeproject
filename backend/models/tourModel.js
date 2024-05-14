const mongoose = require('mongoose')
const slugify = require('slugify')
const validator = require('validator')
const { Schema } = mongoose;

const tourSchema = new Schema({
    name:  {
        type: String,
        required: [true, 'A tour must have a name'],
        trim: true,
        maxlength: [40, 'A tour name must have less or equal then 40 characters'],
        minlength: [10, 'A tour name must have more or equal then 10 characters']
    },
    duration:{
        type: Number,
        required: [true, 'A tour must have a duration']
    },
    maxGroupSize: {
        type: Number,
        required: [true, 'A tour must have a group size']
    },
    difficulty: {
        type: String,
        required: [true, 'A tour must have a difficulty'],
        enum: {
            values: ['easy', 'medium', 'difficult'],
            message: 'Difficulty is either: easy, medium, difficult'
        }
    },
    price: {
        type: Number,
        required: [true, 'A tour must have a price']
    },
    summary: {
        type: String,
        trim: true,
        required: [true, 'A tour must have a summary']
    },
    description: {
        type: String,
        trim: true
    },
    imageCover: {
        type: String
    },
    images: [String],
    startDates: [Date],
    secretTour: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now(),
        select: false
    },
    addedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    },
    guide: 
        {
            type: mongoose.Schema.ObjectId,
            ref: 'User'
        }
        
    ,
  }, {
    toJSON: { virtuals: true },
  });

tourSchema.index({price: 1, ratingsAverage: -1});
tourSchema.index({slug: 1});
tourSchema.index({startLocation: '2dsphere'});

tourSchema.virtual('durationWeeks').get(function(){
    return this.duration / 7
})

tourSchema.virtual('reviews', {
    ref: 'Review',
    foreignField: 'tour',
    localField: '_id'
})

tourSchema.pre('save', function(next){
    this.slug = slugify(this.name, {lower: true})
    next()
});



tourSchema.post(/^find/, function(docs, next){
    console.log(`Query took ${Date.now() - this.start} milliseconds`)
    next()
})


const Tour = mongoose.model('Tour', tourSchema);

module.exports = Tour;