import axios from "axios";
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { serverEndpoint } from "../../config/config";
import { DataGrid } from "@mui/x-data-grid";
import { Bar, Pie } from 'react-chartjs-2';
import DatePicker from 'react-datepicker';
import 'react-datepicker/dist/react-datepicker.css';
import './AnalyticsDashboard.css';

import {
    Chart as ChartJS,
    BarElement,
    CategoryScale,
    LinearScale,
    ArcElement,
    Tooltip,
    Legend,
    Title
} from 'chart.js';

ChartJS.register(
    BarElement,
    CategoryScale,
    LinearScale,
    ArcElement,
    Tooltip,
    Legend,
    Title
);

const formatDate = (isoDateString) => {
    if(!isoDateString) return '';

    try{
        const date = new Date(isoDateString);

        // July 10, 2025
        return new Intl.DateTimeFormat('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        }).format(date);
    }catch(error){
        console.log(error);
        return '';
    }
};

function AnalyticsDashboard() {
    const { id }  = useParams();
    const navigate = useNavigate();
    const [analyticsData, setAnalyticsData] = useState([]);
    const [fromDate, setFromDate] = useState(null);
    const [toDate, setToDate] = useState(null);
    
    const fetchAnalytics = async () => {
        try{
            const response = await axios.get(`${serverEndpoint}/links/analytics`,{
                params: {
                    linkId :id,
                    from: fromDate,
                    to: toDate
                },
                withCredentials: true
            });
            setAnalyticsData(response.data);
        }catch(error){
            console.log(error);
            navigate('/error');
        }
    };

    const groupBy = (key) => {
         return analyticsData.reduce((acc, item) => {
            const label = item[key] || 'unknown';
            acc[label] = (acc[label] || 0) + 1;
            return acc;
        }, {});
    };

    const clicksByCity = groupBy('city');
    const clicksByBrowser = groupBy('browser');

    const columns = [
        { field: 'ip', headerName: 'IP Adderss', flex: 1 },
        { field: 'city', headerName: 'City', flex: 1 },
        { field: 'country', headerName: 'Country', flex: 1 },
        { field: 'region', headerName: 'Region', flex: 1 },
        { field: 'isp', headerName: 'ISP', flex: 1 },
        { field: 'deviceType', headerName: 'Device', flex: 1 },
        { field: 'browser', headerName: 'Browser', flex: 1 },
        { 
            field: 'clickedAt', headerName: 'Clicked At', flex: 1, renderCell: (params) => (
                <span>{formatDate(params.row.clickedAt)}</span>
            ) 
        },
    ];

    useEffect(() => {
        fetchAnalytics();
    },[analyticsData, fromDate, toDate]);

    return (
        <div className="analytics-dashboard-container">
            <div className="container">
                {/* Header Section */}
                <div className="analytics-header">
                    <h1>Analytics Dashboard</h1>
                    <p>Detailed analytics for Link ID: {id}</p>
                </div>

                {/* Stats Cards */}
                <div className="stats-cards">
                    <div className="stat-card">
                        <div className="stat-icon">
                            <i className="fas fa-mouse-pointer"></i>
                        </div>
                        <div className="stat-number">{analyticsData.length}</div>
                        <div className="stat-label">Total Clicks</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-icon">
                            <i className="fas fa-globe"></i>
                        </div>
                        <div className="stat-number">{Object.keys(clicksByCity).length}</div>
                        <div className="stat-label">Cities</div>
                    </div>
                    <div className="stat-card">
                        <div className="stat-icon">
                            <i className="fas fa-browser"></i>
                        </div>
                        <div className="stat-number">{Object.keys(clicksByBrowser).length}</div>
                        <div className="stat-label">Browsers</div>
                    </div>
                </div>

                {/* Filters Section */}
                <div className="filters-section">
                    <h5>Date Filters</h5>
                    <div className="date-picker-container">
                        <div className="date-picker-wrapper">
                            <DatePicker
                                selected={fromDate}
                                onChange={(date) => setFromDate(date)}
                                className="form-control"
                                placeholderText="From Date"
                                dateFormat="MMM dd, yyyy"
                            />
                        </div>
                        <div className="date-picker-wrapper">
                            <DatePicker
                                selected={toDate}
                                onChange={(date) => setToDate(date)}
                                className="form-control"
                                placeholderText="To Date"
                                dateFormat="MMM dd, yyyy"
                            />
                        </div>
                    </div>
                </div>

                {/* Charts Section */}
                <div className="charts-section">
                    <div className="row">
                        {/* Bar Chart: Clicks by City */}
                        <div className="col-md-8">
                            <div className="chart-container">
                                <h5>Clicks by City</h5>
                                <hr />
                                <Bar
                                    data={{
                                        labels: Object.keys(clicksByCity),
                                        datasets: [
                                            {
                                                label: 'Clicks',
                                                data: Object.values(clicksByCity),
                                                backgroundColor: 'rgba(102, 126, 234, 0.6)',
                                                borderColor: 'rgba(102, 126, 234, 1)',
                                                borderWidth: 1,
                                            }
                                        ]
                                    }}
                                    options={{ 
                                        responsive: true,
                                        plugins: {
                                            legend: {
                                                display: false
                                            }
                                        }
                                    }}
                                />
                            </div>
                        </div>

                        {/* Pie Chart: Clicks by Browser */}
                        <div className="col-md-4">
                            <div className="chart-container pie-chart-container">
                                <h5>Clicks by Browser</h5>
                                <hr />
                                <Pie
                                    data={{
                                        labels: Object.keys(clicksByBrowser),
                                        datasets: [
                                            {
                                                data: Object.values(clicksByBrowser),
                                                backgroundColor: [
                                                    '#FF6384',
                                                    '#36A2EB',
                                                    '#FFCE56',
                                                    '#4BC0C0',
                                                    '#9966FF',
                                                    '#FF9F40',
                                                ],
                                            }
                                        ]
                                    }}
                                    options={{ 
                                        responsive: true,
                                        plugins: {
                                            legend: {
                                                position: 'bottom'
                                            }
                                        }
                                    }}
                                />
                            </div>
                        </div>
                    </div>
                </div>

                {/* Data Grid Section */}
                <div className="analytics-grid">
                    <DataGrid
                        getRowId={(row) => row._id}
                        rows={analyticsData} 
                        columns={columns}
                        initialState={{
                            pagination: {
                                paginationModel: { pageSize: 20, page: 0}
                            }
                        }}
                        pageSizeOptions={[20,50,100]}
                        disableRowSelectionOnClick
                        showToolbar
                        sx={{
                            fontFamily: 'inherit'
                        }}
                    />
                </div>
            </div>
        </div>
    );
}

export default AnalyticsDashboard;
