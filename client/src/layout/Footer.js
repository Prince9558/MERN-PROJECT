import "./Footer.css";

function Footer() {
    return (
        <div className="container-fluid">
        <footer className="footer-modern">
            
                <div className="footer-content">
                    <div className="footer-section">
                        <h5 className="footer-title">Affiliate++</h5>
                        <p className="footer-description">
                            The ultimate platform for managing your affiliate links, tracking analytics, 
                            and maximizing your earnings.
                        </p>
                        <div className="social-links">
                            <a href="#" className="social-link">
                                <i className="fab fa-facebook"></i>
                            </a>
                            <a href="#" className="social-link">
                                <i className="fab fa-twitter"></i>
                            </a>
                            <a href="#" className="social-link">
                                <i className="fab fa-linkedin"></i>
                            </a>
                            <a href="#" className="social-link">
                                <i className="fab fa-instagram"></i>
                            </a>
                        </div>
                    </div>
                </div>
                <div className="footer-bottom">
                    <div className="footer-copyright">
                        <p>&copy; 2025 Affiliate++. All rights reserved.</p>
                    </div>
                </div>
            
        </footer>
        </div>
    );
}

export default Footer;