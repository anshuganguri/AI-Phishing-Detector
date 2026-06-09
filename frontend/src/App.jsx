// src/App.jsx
// Root component: manages page routing and wraps Header + pages

import { useState } from 'react'
import Header  from './components/Header'
import Home    from './pages/Home'
import History from './pages/History'

export default function App() {
  const [activePage, setActivePage] = useState('home')

  return (
    <>
      <Header activePage={activePage} setActivePage={setActivePage} />
      {activePage === 'home'    && <Home />}
      {activePage === 'history' && <History />}
    </>
  )
}
