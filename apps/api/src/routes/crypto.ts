import express, { Request, Response } from "express";
import { prisma } from "@swiftza/database";
import { requireAuth, requireRole } from "../middleware";

const router = express.Router();

/**
 * POST /api/orders/:orderId/crypto-proof
 * Upload USDT payment proof
 */
router.post(
  "/:orderId/crypto-proof",
  requireAuth,
  async (req: Request, res: Response) => {
    try {
      const { orderId } = req.params;
      const { screenshotUrl, transactionHash } = req.body;

      // Get order
      const order = await prisma.order.findUnique({
        where: { id: orderId },
      });

      if (!order) {
        return res.status(404).json({ error: "Order not found" });
      }

      if (order.userId !== req.jwtPayload!.userId) {
        return res.status(403).json({ error: "Unauthorized" });
      }

      if (order.paymentMethod !== "CRYPTO") {
        return res.status(400).json({ error: "Order payment method is not crypto" });
      }

      // Create or update proof
      const proof = await prisma.cryptoProof.upsert({
        where: { orderId },
        create: {
          orderId,
          userId: req.jwtPayload!.userId,
          expectedAmount: order.total,
          walletAddress: process.env.CRYPTO_WALLET_ADDRESS || "",
          screenshotUrl,
          transactionHash,
          expiresAt: new Date(Date.now() + 48 * 60 * 60 * 1000), // 48 hours
        },
        update: {
          screenshotUrl,
          transactionHash,
          submittedAt: new Date(),
          status: "PENDING", // Reset status for re-review
        },
      });

      res.json(proof);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

/**
 * GET /api/admin/crypto-proofs
 * List pending crypto proofs for review (staff:crypto, admin)
 */
router.get(
  "/",
  requireAuth,
  requireRole("ADMIN", "STAFF_CRYPTO"),
  async (req: Request, res: Response) => {
    try {
      const { status = "PENDING", page = 1, limit = 20 } = req.query;

      const skip = (Number(page) - 1) * Number(limit);

      const [proofs, total] = await Promise.all([
        prisma.cryptoProof.findMany({
          where: { status: status as any },
          include: {
            order: { select: { id: true, orderNumber: true, total: true } },
            user: { select: { id: true, email: true, firstName: true, lastName: true } },
          },
          skip,
          take: Number(limit),
          orderBy: { submittedAt: "asc" },
        }),
        prisma.cryptoProof.count({ where: { status: status as any } }),
      ]);

      res.json({
        data: proofs,
        pagination: {
          page: Number(page),
          limit: Number(limit),
          total,
          pages: Math.ceil(total / Number(limit)),
        },
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

/**
 * GET /api/admin/crypto-proofs/:proofId
 * Get proof detail
 */
router.get(
  "/:proofId",
  requireAuth,
  requireRole("ADMIN", "STAFF_CRYPTO"),
  async (req: Request, res: Response) => {
    try {
      const proof = await prisma.cryptoProof.findUnique({
        where: { id: req.params.proofId },
        include: {
          order: true,
          user: true,
        },
      });

      if (!proof) {
        return res.status(404).json({ error: "Proof not found" });
      }

      res.json(proof);
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

/**
 * PATCH /api/admin/crypto-proofs/:proofId
 * Approve or reject crypto proof
 */
router.patch(
  "/:proofId",
  requireAuth,
  requireRole("ADMIN", "STAFF_CRYPTO"),
  async (req: Request, res: Response) => {
    try {
      const { action, rejectionReason } = req.body;

      if (!["APPROVE", "REJECT"].includes(action)) {
        return res.status(400).json({ error: "Invalid action" });
      }

      const proof = await prisma.cryptoProof.findUnique({
        where: { id: req.params.proofId },
        include: { order: true },
      });

      if (!proof) {
        return res.status(404).json({ error: "Proof not found" });
      }

      if (action === "APPROVE") {
        // Update proof status
        const updated = await prisma.cryptoProof.update({
          where: { id: req.params.proofId },
          data: {
            status: "APPROVED",
            reviewedBy: req.jwtPayload!.userId,
            reviewedAt: new Date(),
          },
        });

        // Update order financial status
        await prisma.order.update({
          where: { id: proof.orderId },
          data: {
            financialStatus: "PAID",
            fulfillmentStatus: "PROCESSING",
          },
        });

        res.json({ success: true, proof: updated });
      } else {
        // Reject
        const updated = await prisma.cryptoProof.update({
          where: { id: req.params.proofId },
          data: {
            status: "REJECTED",
            reviewedBy: req.jwtPayload!.userId,
            reviewedAt: new Date(),
            rejectionReason,
          },
        });

        res.json({ success: true, proof: updated });
      }
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

export default router;
