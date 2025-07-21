import { useState } from "react";
import axios from 'axios';
import { GoogleOAuthProvider, GoogleLogin } from '@react-oauth/google';
import { serverEndpoint } from "../config/config";
import { useDispatch } from "react-redux";
import { SET_USER } from "../redux/user/actions";
import { Link, useNavigate } from "react-router-dom";
import "./Register.css";

function Register() {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        username: "",
        password: "",
        name: ""
    });

    const [errors, setErrors] = useState({});
    const [isLoading, setIsLoading] = useState(false);

    const handleChange = (event) => {
        const name = event.target.name;
        const value = event.target.value;

        setFormData({
            ...formData,
            [name]: value
        });
    };

    const validate = () => {
        let newErrors = {};
        let isValid = true;
        if (formData.username.length === 0) {
            newErrors.username = "Username is mandatory";
            isValid = false;
        }

        if (formData.password.length === 0) {
            newErrors.password = "Password is mandatory";
            isValid = false;
        }

        if (formData.name.length === 0) {
            newErrors.name = "Name is mandatory";
            isValid = false;
        }

        setErrors(newErrors);
        return isValid;
    }

    const handleSubmit = async (event) => {
        event.preventDefault();

        if (validate()) {
            setIsLoading(true);
            const body = {
                username: formData.username,
                password: formData.password,
                name: formData.name
            };
            const configuration = {
                withCredentials: true
            };
            try {
                const response = await axios.post(
                    `${serverEndpoint}/auth/register`,
                    body, configuration);
                dispatch({
                    type: SET_USER,
                    payload: response.data.user
                });
                navigate('/dashboard');
            } catch (error) {
                if (error?.response?.status === 401) {
                    setErrors({ message: 'User exists with the given email' });
                } else if (error.code === 'ERR_NETWORK') {
                    setErrors({ message: 'Network error. Please check your connection and try again.' });
                } else {
                    setErrors({ message: 'Something went wrong, please try again' });
                }
            } finally {
                setIsLoading(false);
            }
        }
    };

    const handleGoogleSignin = async (authResponse) => {
        setIsLoading(true);
        try {
            const response = await axios.post(`${serverEndpoint}/auth/google-auth`, {
                idToken: authResponse.credential
            }, {
                withCredentials: true,
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            dispatch({
                type: SET_USER,
                payload: response.data.userDetails
            });
            navigate('/dashboard');
        } catch (error) {
            console.log('Google Auth Error:', error);
            if (error.code === 'ERR_NETWORK') {
                setErrors({ message: 'Network error. Please check your connection and try again.' });
            } else if (error.response?.status === 401) {
                setErrors({ message: 'Google authentication failed. Please try again.' });
            } else {
                setErrors({ message: 'Something went wrong while google signin' });
            }
        } finally {
            setIsLoading(false);
        }
    };

    const handleGoogleSigninFailure = async (error) => {
        console.log('Google OAuth Error:', error);
        setErrors({ message: 'Something went wrong while google signin' });
    };

    return (
        <div className="auth-container">
            <div className="auth-background">
                <div className="auth-card">
                    <div className="auth-header">
                        <div className="auth-logo">
                            <i className="fas fa-user-plus"></i>
                        </div>
                        <h2 className="auth-title">Join Affiliate++</h2>
                        <p className="auth-subtitle">Create your account and start earning</p>
                    </div>

                    {/* Error Alert */}
                    {errors.message && (
                        <div className="auth-alert auth-alert-danger">
                            <i className="fas fa-exclamation-circle"></i>
                            {errors.message}
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="auth-form">
                        <div className="form-group">
                            <label htmlFor="name" className="form-label">
                                <i className="fas fa-user"></i>
                                Full Name
                            </label>
                            <input
                                type="text"
                                className={`form-input ${errors.name ? 'is-invalid' : ''}`}
                                id="name"
                                name="name"
                                value={formData.name}
                                onChange={handleChange}
                                placeholder="Enter your full name"
                                disabled={isLoading}
                            />
                            {errors.name && (
                                <div className="form-error">
                                    <i className="fas fa-times-circle"></i>
                                    {errors.name}
                                </div>
                            )}
                        </div>

                        <div className="form-group">
                            <label htmlFor="username" className="form-label">
                                <i className="fas fa-at"></i>
                                Username
                            </label>
                            <input
                                type="text"
                                className={`form-input ${errors.username ? 'is-invalid' : ''}`}
                                id="username"
                                name="username"
                                value={formData.username}
                                onChange={handleChange}
                                placeholder="Choose a username"
                                disabled={isLoading}
                            />
                            {errors.username && (
                                <div className="form-error">
                                    <i className="fas fa-times-circle"></i>
                                    {errors.username}
                                </div>
                            )}
                        </div>

                        <div className="form-group">
                            <label htmlFor="password" className="form-label">
                                <i className="fas fa-lock"></i>
                                Password
                            </label>
                            <input
                                type="password"
                                className={`form-input ${errors.password ? 'is-invalid' : ''}`}
                                id="password"
                                name="password"
                                value={formData.password}
                                onChange={handleChange}
                                placeholder="Create a strong password"
                                disabled={isLoading}
                            />
                            {errors.password && (
                                <div className="form-error">
                                    <i className="fas fa-times-circle"></i>
                                    {errors.password}
                                </div>
                            )}
                        </div>

                        <button 
                            type="submit" 
                            className={`auth-btn auth-btn-primary ${isLoading ? 'loading' : ''}`}
                            disabled={isLoading}
                        >
                            {isLoading ? (
                                <>
                                    <i className="fas fa-spinner fa-spin"></i>
                                    Creating Account...
                                </>
                            ) : (
                                <>
                                    <i className="fas fa-user-plus"></i>
                                    Create Account
                                </>
                            )}
                        </button>
                    </form>

                    <div className="auth-divider">
                        <span className="divider-text">OR</span>
                    </div>

                    <div className="google-auth-container">
                        <GoogleOAuthProvider clientId="633130674681-kf65cmvss4kpst12piu8kdlrubejb4je.apps.googleusercontent.com">
                            <GoogleLogin
                                onSuccess={handleGoogleSignin}
                                onError={handleGoogleSigninFailure}
                                className="google-btn"
                                disabled={isLoading}
                                useOneTap={false}
                            />
                        </GoogleOAuthProvider>
                    </div>

                    <div className="auth-footer">
                        <p>Already have an account? <Link to="/login" className="auth-link">Sign in</Link></p>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Register;