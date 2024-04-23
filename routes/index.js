const express = require('express');
const router = express.Router();
require('dotenv').config()
const bcrypt = require('bcryptjs')
const extraBcryptString = process.env.EXTRA_BCRYPT_STRING
const jwt = require("jsonwebtoken");
const mongoose = require('mongoose')
const Schema = mongoose.Schema

const userSchema = new Schema({
  email: { type: String, required: true },
  password: { type: String, required: true },
  purchases: [{
    productId: { type: Schema.Types.ObjectId, ref: 'Item' },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    purchaseDate: { type: Date, required: true },
  }]
})

userSchema.statics.findByTag = async function(tag) {
  const user = await this.findOne({ tag: tag });
  return user;
};

const User = mongoose.model('User', userSchema)

let nextUserId = 0;

const jwtSecret = process.env.JWT_STRING;

router.post('/signin', async (req, res, next) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      let errorMessage = '';
      if (!email && !password) {
        errorMessage = 'Email and password are required';
      } else if (!email) {
        errorMessage = 'Email is required';
      } else {
        errorMessage = 'Password is required';
      }
      return res.status(400).json({ success: false, msg: errorMessage });
    }

    const user = await User.findOne({ email });
    console.log(user)

    if (!user) {
      return res.status(401).json({ success: false, msg: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password + extraBcryptString, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ success: false, msg: 'Error, please check your email and password' });
    }

    const token = jwt.sign({ email: user.email, userId: user._id }, jwtSecret, { expiresIn: '1h' });
    res.status(200).json({ success: true, token, user });
  } catch (error) {
    console.error('Error signing in:', error);
    res.status(500).json({ success: false, msg: 'Internal server error' });
  }
});

router.post('/signup', async (req, res, next) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      let errorMessage = '';
      if (!email && !password) {
        errorMessage = 'Email and password are required';
      } else if (!email) {
        errorMessage = 'Email is required';
      } else {
        errorMessage = 'Password is required';
      }
      return res.status(400).json({ success: false, msg: errorMessage });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, msg: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password + process.env.EXTRA_BCRYPT_STRING, 12);

    const newUser = new User({
      email,
      password: hashedPassword,
      cart: []
    });
    nextUserId++;

    await newUser.save();

    res.status(201).json({ success: true, msg: 'User created successfully' });
  } catch (error) {
    console.error('Error signing up:', error);
    res.status(500).json({ success: false, msg: 'Internal server error' });
  }
});

router.get('/signout', (req, res, next) => {
  res.setHeader('Authorization', '');
  res.status(200).json({ success: true, msg: 'You are signed out' });
});

function checkAuth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ success: false, msg: 'No token provided' });
  }

  jwt.verify(token.split(' ')[1], jwtSecret, (err, decoded) => {
    if (err) {
      if (err instanceof jwt.TokenExpiredError) {
        res.setHeader('Authorization', '');
        return res.status(401).json({ success: false});
      }
      return res.status(401).json({ success: false});
    }
    req.userId = decoded.userId;
    next();
  });
}

router.get('/showUsers', async (req, res, next) => {
  try {
    let allEmails = "";
    const users = await User.find();
    console.log(users)
    users.forEach((user => { 
      allEmails += user.email;
    }))

    res.status(200).json(allEmails);
  } catch (error) {
    console.error('Error fetching emails:', error);
    res.status(500).json({ success: false, msg: 'Internal server error' });
  }
});

router.get('/clearCart', async (req, res, next) => {
  const userId = "661d273fabad7263e2d04d97";

  try {
    const user = await User.findById(userId);
    if (!user) {
      console.log('User not found');
      return res.status(404).json({ success: false, msg: 'User not found' });
    }
    user.purchases = [];
    await user.save();

    console.log('User cart cleared successfully');
    res.status(200).json({ success: true, msg: 'User cart cleared successfully' });
  } catch (error) {
    console.error('Error clearing cart:', error);
    res.status(500).json({ success: false, msg: 'Internal server error' });
  }
});


const itemSchema = new Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true }
});

const Item = mongoose.model('Item', itemSchema);

router.get('/items', async (req, res, next) => {
  try {
    const items = await Item.find();
    res.status(200).json({ success: true, items });
  } catch (error) {
    console.error('Error fetching items:', error);
    res.status(500).json({ success: false, msg: 'Internal server error' });
  }
});


router.post('/addFlight', checkAuth, async (req, res, next) => {
  console.log('Request body:', req.body);
  const { tag, otherTags } = req.body; 
  const userTag = tag.tag;

  try {
    const user = await User.findByTag(userTag);
    if (!user) {
      console.log('User not found');
      return res.status(404).json({ success: false, msg: 'User not found' });
    }
    
    console.log('User found:', user);

    let totalPrice = 0;
    const purchaseDetails = [];

    for (const otherTag of otherTags) {
      const product = await Item.findOne({ productCode: otherTag });
      
      if (product) {
        console.log('Product found:', product);
        totalPrice += product.price;

        product.stock -= 1;
        await product.save();
        console.log(`Stock updated for product with product code ${otherTag}`);

        const purchase = {
          productId: product._id,
          name: product.name,
          price: product.price,
          purchaseDate: new Date(),
        };
        purchaseDetails.push(purchase);
      } else {
        console.log(`Product with product code ${otherTag} not found`);
      }
    }

    console.log('Total Price:', totalPrice);

    user.balance -= totalPrice;
    user.purchases.push(...purchaseDetails);
    await user.save();

    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Error buying products:', error);
    res.status(500).json({ success: false, msg: 'Internal server error' });
  }
});


router.get('/viewCart', checkAuth, async (req, res, next) => {
  try {
    const userId = req.session.userId;

    const user = await User.findById(userId).populate('purchases.productId');

    if (!user || !user.purchases || user.purchases.length === 0) {
      console.log('Cart is empty');
      return res.status(200).json({ success: true, msg: 'Cart is empty' });
    }

    const purchaseDetails = user.purchases.map(item => ({
      name: item.name,
      price: item.price,
      purchaseDate: item.purchaseDate,
    }));

    res.status(200).json({ success: true, purchases: purchaseDetails });
  } catch (error) {
    console.error('Error viewing cart:', error);
    res.status(500).json({ success: false, msg: 'Internal server error' });
  }
});


router.get('/getDestinationID', checkAuth, async (req, res) => {
  const { destination } = req.query;
  console.log("Revieved: ", destination)
  const url = new URL('https://booking-com.p.rapidapi.com/v1/hotels/locations');
  url.searchParams.append('name', destination);
  url.searchParams.append('locale', 'en-gb');

  try {
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'X-RapidAPI-Key': '05a223207amshf68f09ccba1f243p140d08jsn5662b6a0529b',
        'X-RapidAPI-Host': 'booking-com.p.rapidapi.com'
      },
    });

    if (!response.ok) {
      const errorData = await response.json();
      console.error("Error from external API:", errorData);
      return res.status(500).json({ success: false, msg: 'Error fetching destination ID' });
    }

    const data = await response.json();
    console.log("Response from external API:", data);

    // Check if data contains valid destination information
    if (!Array.isArray(data) || data.length === 0 || !data[0].dest_id) {
      console.error("Invalid destination data received:", data);
      return res.status(500).json({ success: false, msg: 'Destination not found' });
    }
    console.log(data);
    const destinationID = data[0].dest_id;

    res.status(200).json({ success: true, destinationID });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.get('/getHotels', checkAuth, async (req, res) => {
  const { hotelID } = req.query;
  const url = new URL('https://booking-com.p.rapidapi.com/v1/hotels/search');
  url.searchParams.append('checkout_date', '2024-09-20');
  url.searchParams.append('order_by', 'popularity');
  url.searchParams.append('filter_by_currency', 'EUR');
  url.searchParams.append('room_number', '1');
  url.searchParams.append('dest_id', hotelID);
  url.searchParams.append('dest_type', 'city');
  url.searchParams.append('adults_number', '2');
  url.searchParams.append('checkin_date', '2024-09-14');
  url.searchParams.append('locale', 'en-gb');
  url.searchParams.append('units', 'metric');
  url.searchParams.append('include_adjacency', 'true');
  url.searchParams.append('children_number', '2');
  url.searchParams.append('page_number', '0');
  
  try {
    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'X-RapidAPI-Key': '05a223207amshf68f09ccba1f243p140d08jsn5662b6a0529b',
        'X-RapidAPI-Host': 'booking-com.p.rapidapi.com'
      },
    });
   
    if (!response.ok) {
      return res.status(500).json({ success: false, msg: "Error Fetching Hotels" });
    }
    
    const fetchedHotels = await response.json();
    console.log(fetchedHotels);

    res.status(200).json({ success: true, fetchedHotels });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


exports.routes = router