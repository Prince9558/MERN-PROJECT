import { Link } from "react-router-dom";
import "./Home.css";

function Home() {
    return (
        <div className="home-container">
            {/* Hero Section */}
            <section className="hero-section">
                <div className="hero-background">
                    <div className="hero-overlay"></div>
                </div>
                <div className="hero-content">
                    <div className="container">
                        <div className="row align-items-center min-vh-100">
                            <div className="col-lg-6">
                                <div className="hero-text">
                                    <h1 className="hero-title">
                                        Transform Your <span className="highlight">Affiliate Marketing</span>
                                    </h1>
                                    <p className="hero-subtitle">
                                        The ultimate platform for managing affiliate links, tracking analytics, 
                                        and maximizing your earnings with powerful tools and insights.
                                    </p>
                                    <div className="hero-stats">
                                        <div className="stat-item">
                                            <div className="stat-number">10K+</div>
                                            <div className="stat-label">Active Users</div>
                                        </div>
                                        <div className="stat-item">
                                            <div className="stat-number">1M+</div>
                                            <div className="stat-label">Links Created</div>
                                        </div>
                                        <div className="stat-item">
                                            <div className="stat-number">$5M+</div>
                                            <div className="stat-label">Revenue Generated</div>
                                        </div>
                                    </div>
                                    <div className="hero-buttons">
                                        <Link to="/register" className="btn btn-primary btn-lg">
                                            <i className="fas fa-rocket me-2"></i>
                                            Get Started Free
                                        </Link>
                                        <Link to="/login" className="btn btn-outline-light btn-lg">
                                            <i className="fas fa-sign-in-alt me-2"></i>
                                            Sign In
                                        </Link>
                                    </div>
                                </div>
                            </div>
                            <div className="col-lg-6">
                                <div className="hero-visual">
                                    <div className="floating-elements">
                                        <div className="floating-card card-1">
                                            <i className="fas fa-chart-line"></i>
                                            <span>Analytics</span>
                                        </div>
                                        <div className="floating-card card-2">
                                            <i className="fas fa-link"></i>
                                            <span>Links</span>
                                        </div>
                                        <div className="floating-card card-3">
                                            <i className="fas fa-dollar-sign"></i>
                                            <span>Earnings</span>
                                        </div>
                                        <div className="floating-card card-4">
                                            <i className="fas fa-users"></i>
                                            <span>Users</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Platform Description Section */}
            <section className="platform-description-section">
                <div className="container">
                    <div className="platform-content text-center">
                        <div className="platform-text">
                            <h2>The Ultimate Platform</h2>
                            <p className="platform-description">
                                The ultimate platform for managing your affiliate links, tracking analytics, 
                                and maximizing your earnings with powerful tools and insights.
                            </p>
                        </div>
                    </div>
                </div>
            </section>

            {/* Features Section */}
            <section className="features-section">
                <div className="container">
                    <div className="section-header text-center">
                        <h2 className="section-title">Why Choose Affiliate++?</h2>
                        <p className="section-subtitle">
                            Powerful features designed to help you succeed in affiliate marketing
                        </p>
                    </div>
                    <div className="features-grid">
                        <div className="feature-card">
                            <div className="feature-icon">
                                <i className="fas fa-chart-line"></i>
                            </div>
                            <h3>Advanced Analytics</h3>
                            <p>Track clicks, conversions, and earnings with detailed analytics and real-time insights.</p>
                        </div>
                        <div className="feature-card">
                            <div className="feature-icon">
                                <i className="fas fa-link"></i>
                            </div>
                            <h3>Smart Link Management</h3>
                            <p>Create, organize, and manage your affiliate links with our intuitive dashboard.</p>
                        </div>
                        <div className="feature-card">
                            <div className="feature-icon">
                                <i className="fas fa-shield-alt"></i>
                            </div>
                            <h3>Secure & Reliable</h3>
                            <p>Bank-level security ensures your data and earnings are always protected.</p>
                        </div>
                        <div className="feature-card">
                            <div className="feature-icon">
                                <i className="fas fa-mobile-alt"></i>
                            </div>
                            <h3>Mobile Responsive</h3>
                            <p>Access your dashboard from anywhere with our mobile-optimized interface.</p>
                        </div>
                        <div className="feature-card">
                            <div className="feature-icon">
                                <i className="fas fa-users"></i>
                            </div>
                            <h3>User Management</h3>
                            <p>Manage multiple users and roles with advanced permission controls.</p>
                        </div>
                        <div className="feature-card">
                            <div className="feature-icon">
                                <i className="fas fa-credit-card"></i>
                            </div>
                            <h3>Payment Integration</h3>
                            <p>Seamless payment processing with multiple payment gateway support.</p>
                        </div>
                    </div>
                </div>
            </section>

            {/* How It Works Section */}
            <section className="how-it-works-section">
                <div className="container">
                    <div className="section-header text-center">
                        <h2 className="section-title">How It Works</h2>
                        <p className="section-subtitle">
                            Get started in just 3 simple steps
                        </p>
                    </div>
                    <div className="steps-container">
                        <div className="step-item">
                            <div className="step-number">1</div>
                            <div className="step-content">
                                <h3>Create Account</h3>
                                <p>Sign up for free and get instant access to our powerful affiliate management tools.</p>
                            </div>
                        </div>
                        <div className="step-item">
                            <div className="step-number">2</div>
                            <div className="step-content">
                                <h3>Add Your Links</h3>
                                <p>Import your existing affiliate links or create new ones with our easy-to-use interface.</p>
                            </div>
                        </div>
                        <div className="step-item">
                            <div className="step-number">3</div>
                            <div className="step-content">
                                <h3>Track & Earn</h3>
                                <p>Monitor your performance with real-time analytics and maximize your earnings.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* Testimonials Section */}
            <section className="testimonials-section">
                <div className="container">
                    <div className="section-header text-center">
                        <h2 className="section-title">What Our Users Say</h2>
                        <p className="section-subtitle">
                            Join thousands of successful affiliates
                        </p>
                    </div>
                    <div className="testimonials-grid">
                        <div className="testimonial-card">
                            <div className="testimonial-content">
                                <p>"Affiliate++ has completely transformed my affiliate marketing business. The analytics are incredible!"</p>
                            </div>
                            <div className="testimonial-author">
                                <div className="author-avatar">
                                    <i className="fas fa-user"></i>
                                </div>
                                <div className="author-info">
                                    <h4>Himanshu Raj</h4>
                                    <span>Digital Marketer</span>
                                </div>
                            </div>
                        </div>
                        <div className="testimonial-card">
                            <div className="testimonial-content">
                                <p>"The link management features are so intuitive. I've increased my earnings by 300%!"</p>
                            </div>
                            <div className="testimonial-author">
                                <div className="author-avatar">
                                    <i className="fas fa-user"></i>
                                </div>
                                <div className="author-info">
                                    <h4>Ranjan Kumar</h4>
                                    <span>Affiliate Manager</span>
                                </div>
                            </div>
                        </div>
                        <div className="testimonial-card">
                            <div className="testimonial-content">
                                <p>"Best affiliate platform I've ever used. The support team is amazing too!"</p>
                            </div>
                            <div className="testimonial-author">
                                <div className="author-avatar">
                                    <i className="fas fa-user"></i>
                                </div>
                                <div className="author-info">
                                    <h4>Kundan Kumar</h4>
                                    <span>Content Creator</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* CTA Section */}
            <section className="cta-section">
                <div className="container">
                    <div className="cta-content text-center">
                        <h2>Ready to Start Your Affiliate Journey?</h2>
                        <p>Join thousands of successful affiliates who trust Affiliate++ for their business.</p>
                        <Link to="/register" className="btn btn-primary btn-lg">
                            <i className="fas fa-rocket me-2"></i>
                            Start Free Trial
                        </Link>
                    </div>
                </div>
            </section>
        </div>
    );
}

export default Home;