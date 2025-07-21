import "./UserFooter.css";

function UserFooter() {
    return (
        <footer className="user-footer">
            <div className="container">
                <div className="footer-content">
                    <div className="footer-section">
                        <h5>Affiliate++</h5>
                        <p>The ultimate platform for managing your affiliate links, tracking analytics, and maximizing your earnings.</p>
                    </div>
                    <div className="footer-section">
                        <h6>Quick Links</h6>
                        <ul className="footer-links">
                            <li><a href="/dashboard">Dashboard</a></li>
                            <li><a href="/manage-payments">Payments</a></li>
                            <li><a href="/users">Users</a></li>
                        </ul>
                    </div>
                    <div className="footer-section">
                        <h6>Support</h6>
                        <ul className="footer-links">
                            <li><a href="#help">Help Center</a></li>
                            <li><a href="#contact">Contact Us</a></li>
                            <li><a href="#docs">Documentation</a></li>
                        </ul>
                    </div>
                    <div className="footer-section">
                        <h6>Connect</h6>
                        <div className="social-links">
                            <a href="#twitter" className="social-link">
                                <i className="fab fa-twitter"></i>
                            </a>
                            <a href="#linkedin" className="social-link">
                                <i className="fab fa-linkedin"></i>
                            </a>
                            <a href="#github" className="social-link">
                                <i className="fab fa-github"></i>
                            </a>
                        </div>
                    </div>
                </div>
                <div className="footer-bottom">
                    <p>&copy; 2024 Affiliate++. All rights reserved.</p>
                </div>
            </div>
        </footer>
    );
}

export default UserFooter;