import { Link } from "react-router-dom";
import "./Header.css";

function Header() {
    return (
        <nav className="navbar navbar-expand-lg navbar-modern">
            <div className="container">
                <Link className="navbar-brand" to="/">
                    <span className="brand-text">Affiliate++</span>
                </Link>
                <button
                    className="navbar-toggler"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#navbarSupportedContent"
                    aria-controls="navbarSupportedContent"
                    aria-expanded="false"
                    aria-label="Toggle navigation"
                >
                    <span className="navbar-toggler-icon"></span>
                </button>
                <div className="collapse navbar-collapse" id="navbarSupportedContent">
                    <ul className="navbar-nav ms-auto mb-2 mb-lg-0">
                        <li className="nav-item">
                            <Link className="nav-link active" aria-current="page" to="/">
                                <i className="fas fa-home"></i> Home
                            </Link>
                        </li>
                        <li className="nav-item">
                            <Link className="nav-link" to="/login">
                                <i className="fas fa-sign-in-alt"></i> Login
                            </Link>
                        </li>
                        <li className="nav-item">
                            <Link className="nav-link btn btn-primary btn-sm" to="/register">
                                <i className="fas fa-user-plus"></i> Register
                            </Link>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>
    );
}

export default Header;
