/*
import { createContext, useContext, useEffect, useState } from 'react';
import axios from 'axios';
import * as SecureStore from 'expo-secure-store';

const TOKEN_KEY = 'my-jwt';
export const API_URL = 'my endpoint';
const AuthContext = createContext({});

export const useAuth = () => {
    return useContext(AuthContext);
};

export const AuthProvider = ({ children }) => {
    const [authState, setAuthState] = useState({
        token: null,
        authenticated: null,
    });

    useEffect(() => {
        const loadToken = async () => {
            const token = await SecureStore.getItemAsync(TOKEN_KEY);
            console.log('stored', token);

            if (token) {
                axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

                setAuthState({
                    token: token,
                    authenticated: true,
                });
            }
        };
        loadToken();
    }, []);

    const login = async (email, password, confirmPassword) => {
        try {
            const result = await axios.post(`${API_URL}/signup`, { email, password, confirmPassword });

            console.log("AuthContext", result)

            setAuthState({
                token: result.data.token,
                authenticated: true
            });

            axios.defaults.header.common['Authorization'] = `Bearer ${result.data.token}`;

            await SecureStore.setItemAsync(TOKEN_KEY, result.data.token);

            return result;
        } catch (e) {
            return { error: true, msg: e.response.data.msg };
        }
    };

    const register = async (email, password) => {
        try {
            return await axios.post(`${API_URL}/signin`, { email, password });
        } catch (e) {
            return { error: true, msg: e.response.data.msg };
        }
    };

    const logout = async (email, password, confirmPassword) => {
        await SecureStore.deleteItemsAsync(TOKEN_KEY);

        axios.defaults.headers.common['Authorization'] = '';

        setAuthState({
            token: null,
            authenticated: false
        });
    };

    const value = {
        onRegister: register,
        onLogin: login,
        onLogout: logout,
        authState
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

*/
///////////////////////////
/*

router.post('/buyProduct', async (req, res, next) => {
  console.log('Request body:', req.body);
  const { products, tag } = req.body; 

  

  try {
    const user = await User.findByTag( tag );
    console.log(user)
    if (!user) {
      return res.status(404).json({ success: false, msg: 'User not found' });
    }

    products.forEach(product => {
      user.purchases.push({
        name: product.name,
        price: product.price,
        purchaseDate: product.purchaseDate,
        amount: product.amount
      });
    });

    await user.save();

    res.status(200).json({ success: true, user });
  } catch (error) {
    console.error('Error buying products:', error);
    res.status(500).json({ success: false, msg: 'Internal server error' });
  }
});
*/