import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'; // Import Router
import Dashboard from './pages/Dashboard'; // Import Dashboard Component

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Dashboard />} />  {/* ✅ Only show Dashboard */}
      </Routes>
    </Router>
  );
}

export default App;
