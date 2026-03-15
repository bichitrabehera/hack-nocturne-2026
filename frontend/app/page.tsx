"use client";
import Features from "@/components/Features";
import Footer from "@/components/Footer";
import Hero from "@/components/Hero";
import Navbar from "@/components/Navbar";

export default function HomePage() {
  return (
    <div className="min-h-screen text-white flex flex-col">
      <Navbar />
      <Hero />
      <Features />
      <Footer />
    </div>
  );
}
