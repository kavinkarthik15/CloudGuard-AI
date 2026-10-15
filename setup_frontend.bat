@echo off
cd /d "d:\CloudGuard AI"
echo Creating frontend with Vite...
call npm create vite@latest frontend -- --template react-ts --yes
cd frontend
echo Installing dependencies...
call npm install
call npm install react-router-dom zustand recharts
call npm install -D tailwindcss postcss autoprefixer
call npm install -D vitest @vitest/ui @testing-library/react @testing-library/user-event @testing-library/jest-dom fast-check jsdom
call npx tailwindcss init -p
echo Done.
