import { useState } from "react";
import axios from 'axios';
import { serverEndpoint } from "../config/config";
import { useDispatch } from "react-redux";
import { SET_USER } from "../redux/user/actions";
import { Link, useNavigate } from "react-router-dom";
import "./Login.css";

function Login() {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        username: '',
        password: ''
    });
    const [errors, setErrors] = useState({});
    const [isLoading, setIsLoading] = useState(false);

    const handleChange = (e) => {
        const name = e.target.name;
        const value = e.target.value;

        setFormData({
            ...formData,
            [name]: value
        });
    };

    const validate = () => {
        let isValid = true;
        let newErrors = {};

        if (formData.username.length === 0) {
            isValid = false;
            newErrors.username = "Username is mandatory";
        }

        if (formData.password.length === 0) {
            isValid = false;
            newErrors.password = "Password is mandatory";
        }

        setErrors(newErrors);
        return isValid;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (validate()) {
            setIsLoading(true);
            // Data to be sent to the server
            const body = {
                username: formData.username,
                password: formData.password
            };
            const config = {
                // Tells axios to include cookie in the request + some other auth headers
                withCredentials: true
            };
            try {
                const response = await axios.post(`${serverEndpoint}/auth/login`, body, config);
                dispatch({
                    type: SET_USER,
                    payload: response.data.user
                });
                navigate('/dashboard');
            } catch (error) {
                console.log(error);
                if (error.response && error.response.data) {
                    if (error.response.data.errors && error.response.data.errors.length > 0) {
                        setErrors({ message: error.response.data.errors[0].msg });
                    } else if (error.response.data.message || error.response.data.error) {
                        setErrors({ message: error.response.data.message || error.response.data.error });
                    } else if (error.response?.status === 401) {
                        setErrors({ message: "Invalid username or password" });
                    } else {
                        setErrors({ message: "Something went wrong, please try again" });
                    }
                } else if (error.code === 'ERR_NETWORK') {
                    setErrors({ message: "Network error. Please check your connection and try again." });
                } else {
                    setErrors({ message: "Something went wrong, please try again" });
                }
            } finally {
                setIsLoading(false);
            }
        }
    };


    return (
        <div className="auth-container">
            <div className="auth-background">
                <div className="auth-card">
                    <div className="auth-header">
                        <div className="auth-logo">
                            <i className="fas fa-user-circle"></i>
                        </div>
                        <h2 className="auth-title">Welcome Back</h2>
                        <p className="auth-subtitle">Sign in to your Affiliate++ account</p>
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
                            <label htmlFor="username" className="form-label">
                                <i className="fas fa-user"></i>
                                Username
                            </label>
                            <input
                                type="text"
                                className={`form-input ${errors.username ? 'is-invalid' : ''}`}
                                id="username"
                                name="username"
                                value={formData.username}
                                onChange={handleChange}
                                placeholder="Enter your username"
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
                                placeholder="Enter your password"
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
                                    Signing In...
                                </>
                            ) : (
                                <>
                                    <i className="fas fa-sign-in-alt"></i>
                                    Sign In
                                </>
                            )}
                        </button>
                    </form>

                    <div className="auth-links">
                        <Link to="/forget-password" className="auth-link">
                            <i className="fas fa-key"></i>
                            Forgot Password?
                        </Link>
                    </div>



                    <div className="auth-footer">
                        <p>Don't have an account? <Link to="/register" className="auth-link">Sign up</Link></p>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default Login;