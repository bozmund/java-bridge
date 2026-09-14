package com.example.demo;

public class ScoreKeeper {
    public enum Rank {
        BRONZE,
        SILVER,
        GOLD
    }

    private int points;
    private Geometry lastPosition;

    public ScoreKeeper() {
        this.points = 0;
        this.lastPosition = new Geometry(0.0, 0.0);
    }

    public int points() {
        return points;
    }

    public void award(int delta) {
        if (delta < 0) {
            delta = 0;
        }
        points += delta;
    }

    public Rank rankOf() {
        if (points >= 3000) {
            return Rank.GOLD;
        }
        if (points >= 1000) {
            return Rank.SILVER;
        }
        return Rank.BRONZE;
    }

    public double bonusDistance(Geometry target) {
        double base = lastPosition == null ? 0.0 : lastPosition.distanceTo(target);
        return base * rankMultiplier();
    }

    private double rankMultiplier() {
        Rank r = rankOf();
        if (r == Rank.GOLD) {
            return 1.5;
        }
        if (r == Rank.SILVER) {
            return 1.25;
        }
        return 1.0;
    }

    public String summary() {
        Inventory inv = new Inventory("scores");
        inv.add("points=" + points);
        return rankOf() + ":" + inv.largest();
    }
}
