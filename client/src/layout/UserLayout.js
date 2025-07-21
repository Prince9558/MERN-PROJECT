import UserFooter from "./UserFooter";
import UserHeader from "./UserHeader";
import "./UserLayout.css";

function UserLayout({ children }) {
    return (
        <div className="user-layout">
            <UserHeader />
            <main className="user-main-content">
                {children}
            </main>
            <UserFooter />
        </div>
    );
}

export default UserLayout;