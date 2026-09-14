package com.example.demo;

public class Geometry {
    private final double x;
    private final double y;

    public Geometry(double x, double y) {
        this.x = x;
        this.y = y;
    }

    public double distanceTo(Geometry other) {
        double dx = this.x - other.x;
        double dy = this.y - other.y;
        return Math.sqrt(dx * dx + dy * dy);
    }

    public double dot(Geometry other) {
        return this.x * other.x + this.y * other.y;
    }

    public Geometry scaled(double factor) {
        return new Geometry(this.x * factor, this.y * factor);
    }

    public boolean isOrigin() {
        return this.x == 0.0 && this.y == 0.0;
    }

    public double coordinate(int axis) {
        return axis == 0 ? this.x : this.y;
    }
}
