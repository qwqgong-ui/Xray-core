package bbr

import (
	"time"

	"github.com/apernet/quic-go/congestion"

	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/common"
)

type ecnBBRPhase uint8

const (
	ecnPhaseFallback ecnBBRPhase = iota
	ecnPhaseFastGrow
	ecnPhaseFreeze
	ecnPhaseShrink
	ecnPhaseDrain
)

const (
	ecnAlphaGain              = 1.0 / 16.0
	ecnMinReduction           = 0.02
	ecnMaxReduction           = 0.50
	ecnFloorReductionEpochs   = 3
	ecnSafetyLossRatio        = 0.10
	ecnPathMigrationDecay     = 0.50
	ecnQueueDrainRTTThreshold = 0.50
	ecnQueueDrainRTTExit      = 0.25
)

type ecnBBRState struct {
	phase   ecnBBRPhase
	capable bool
	failed  bool

	alpha     float64
	lastRatio float64

	btlBwFloor    Bandwidth
	inflightFloor congestion.ByteCount

	freezePacing   Bandwidth
	freezeInflight congestion.ByteCount
	shrinkPacing   Bandwidth
	shrinkInflight congestion.ByteCount

	ceSamples     uint32
	ceEpochs      uint32
	shrinkApplied bool
	shrinkPending bool
	pendingSample bool
	pendingCE     bool
	rttDrain      bool
}

func (b *bbrSender) OnECNFeedback(capable, failed bool, ect0, ect1, ecnce uint64) {
	state := &b.ecn
	state.pendingSample = false
	state.pendingCE = false

	if failed {
		state.capable = false
		state.failed = true
		state.phase = ecnPhaseFallback
		state.ceSamples = 0
		state.ceEpochs = 0
		state.shrinkPending = false
		state.rttDrain = false
		return
	}
	if !capable {
		state.capable = false
		state.failed = false
		state.phase = ecnPhaseFallback
		state.ceSamples = 0
		state.shrinkPending = false
		state.rttDrain = false
		return
	}

	state.capable = true
	state.failed = false
	total := float64(ect0) + float64(ect1) + float64(ecnce)
	if total == 0 {
		return
	}

	state.lastRatio = float64(ecnce) / total
	state.alpha = (1-ecnAlphaGain)*state.alpha + ecnAlphaGain*state.lastRatio
	state.pendingSample = true
	state.pendingCE = ecnce != 0

	if ecnce == 0 {
		state.phase = ecnPhaseFastGrow
		state.ceSamples = 0
		state.ceEpochs = 0
		state.shrinkApplied = false
		state.shrinkPending = false
		state.shrinkPacing = 0
		state.shrinkInflight = 0
		return
	}

	if state.ceSamples == 0 {
		state.phase = ecnPhaseFreeze
		state.ceSamples = 1
		state.ceEpochs = 0
		state.freezePacing = b.PacingRate()
		state.freezeInflight = b.congestionWindow
		state.shrinkPacing = state.freezePacing
		state.shrinkInflight = state.freezeInflight
		state.shrinkApplied = false
		state.shrinkPending = false
		state.rttDrain = false
		return
	}

	state.ceSamples++
	state.phase = ecnPhaseShrink
	state.shrinkPending = true
	state.rttDrain = false
}

func (b *bbrSender) currentECNPhase() ecnBBRPhase {
	if b.ecn.phase == ecnPhaseFastGrow && (b.ecn.rttDrain || b.mode == bbrModeDrain || b.mode == bbrModeProbeRtt) {
		return ecnPhaseDrain
	}
	return b.ecn.phase
}

func (b *bbrSender) applyECNPolicy(isRoundStart, hasSafetyLoss bool) {
	state := &b.ecn
	defer func() {
		state.pendingSample = false
		state.pendingCE = false
	}()
	if !state.capable || state.failed {
		return
	}

	if state.pendingSample && !state.pendingCE && !hasSafetyLoss {
		state.btlBwFloor = max(state.btlBwFloor, b.bandwidthEstimate())
		state.inflightFloor = max(state.inflightFloor, b.congestionWindow)
	}

	switch state.phase {
	case ecnPhaseFreeze:
		if !hasSafetyLoss {
			b.pacingRate = state.freezePacing
			b.congestionWindow = clampWindow(state.freezeInflight, b.minCongestionWindow, b.maxCongestionWindow)
		} else {
			b.pacingRate = min(b.pacingRate, state.freezePacing)
			b.congestionWindow = min(b.congestionWindow, state.freezeInflight)
		}
		return
	case ecnPhaseShrink:
		b.applyECNShrink(isRoundStart)
		return
	case ecnPhaseFastGrow:
		b.updateECNQueueWatchdog()
		if b.mode == bbrModeDrain || b.mode == bbrModeProbeRtt {
			return
		}
		if state.rttDrain {
			base := max(state.btlBwFloor, b.bandwidthEstimate())
			target := Bandwidth(b.drainGain * float64(base))
			if target != 0 {
				b.pacingRate = min(b.pacingRate, target)
			}
			b.congestionWindow = min(b.congestionWindow, b.getTargetCongestionWindow(1))
			b.congestionWindow = max(b.congestionWindow, b.minCongestionWindow)
			return
		}
		if hasSafetyLoss {
			return
		}
		base := max(state.btlBwFloor, b.bandwidthEstimate())
		if base != 0 {
			b.pacingRate = max(b.pacingRate, Bandwidth(b.highGain*float64(base)))
		}
		targetWindow := max(state.inflightFloor, b.getTargetCongestionWindow(b.highCwndGain))
		b.congestionWindow = clampWindow(max(b.congestionWindow, targetWindow), b.minCongestionWindow, b.maxCongestionWindow)
	}
}

func (b *bbrSender) applyECNShrink(isRoundStart bool) {
	state := &b.ecn
	if state.shrinkPending && (!state.shrinkApplied || isRoundStart) {
		reduction := state.alpha / 2
		reduction = max(ecnMinReduction, min(ecnMaxReduction, reduction))
		factor := 1 - reduction
		state.shrinkPacing = scaleBandwidth(state.shrinkPacing, factor)
		state.shrinkInflight = scaleWindow(state.shrinkInflight, factor)
		state.ceEpochs++
		state.shrinkApplied = true
		state.shrinkPending = false
		if state.ceEpochs >= ecnFloorReductionEpochs {
			state.btlBwFloor = scaleBandwidth(state.btlBwFloor, factor)
			state.inflightFloor = scaleWindow(state.inflightFloor, factor)
			state.inflightFloor = max(state.inflightFloor, b.minCongestionWindow)
		}
	}

	state.shrinkPacing = max(state.shrinkPacing, state.btlBwFloor)
	state.shrinkInflight = max(state.shrinkInflight, state.inflightFloor)
	if state.shrinkPacing != 0 {
		b.pacingRate = max(state.btlBwFloor, min(b.pacingRate, state.shrinkPacing))
	}
	if state.shrinkInflight != 0 {
		b.congestionWindow = max(state.inflightFloor, min(b.congestionWindow, state.shrinkInflight))
	}
	b.congestionWindow = max(b.congestionWindow, b.minCongestionWindow)
}

func (b *bbrSender) updateECNQueueWatchdog() {
	minRTT := b.getMinRtt()
	latestRTT := b.rttStats.LatestRTT()
	if minRTT <= 0 || latestRTT <= 0 {
		return
	}
	if latestRTT > minRTT+timeFraction(minRTT, ecnQueueDrainRTTThreshold) {
		b.ecn.rttDrain = true
		return
	}
	if latestRTT <= minRTT+timeFraction(minRTT, ecnQueueDrainRTTExit) {
		b.ecn.rttDrain = false
	}
}

func (b *bbrSender) hasSafetyLoss(priorInFlight congestion.ByteCount, lostPackets []congestion.LostPacketInfo) bool {
	if len(lostPackets) == 0 {
		return false
	}
	if !b.ecn.capable || b.ecn.failed {
		return true
	}
	var lost congestion.ByteCount
	for _, packet := range lostPackets {
		lost += packet.BytesLost
	}
	return priorInFlight <= 0 || float64(lost)/float64(priorInFlight) >= ecnSafetyLossRatio
}

func (b *bbrSender) OnPathMigration() {
	now := b.clock.Now()
	state := b.ecn
	state.phase = ecnPhaseFallback
	state.capable = false
	state.failed = false
	state.alpha = 0
	state.lastRatio = 0
	state.btlBwFloor = scaleBandwidth(state.btlBwFloor, ecnPathMigrationDecay)
	state.inflightFloor = scaleWindow(state.inflightFloor, ecnPathMigrationDecay)
	if state.inflightFloor != 0 {
		state.inflightFloor = max(state.inflightFloor, b.minCongestionWindow)
	}
	state.freezePacing = 0
	state.freezeInflight = 0
	state.shrinkPacing = 0
	state.shrinkInflight = 0
	state.ceSamples = 0
	state.ceEpochs = 0
	state.shrinkApplied = false
	state.shrinkPending = false
	state.pendingSample = false
	state.pendingCE = false
	state.rttDrain = false
	b.ecn = state

	b.sampler = newBandwidthSampler(roundTripCount(bandwidthWindowSize))
	b.maxBandwidth = NewWindowedFilter(roundTripCount(bandwidthWindowSize), MaxFilter[Bandwidth])
	b.applyProfile(b.profile)
	b.pacer = common.NewPacer(b.bandwidthForPacer)
	b.roundTripCount = 0
	b.currentRoundTripEnd = b.lastSentPacket
	b.numLossEventsInRound = 0
	b.bytesLostInRound = 0
	b.minRtt = 0
	b.minRttTimestamp = now
	b.pacingRate = scaleBandwidth(b.pacingRate, ecnPathMigrationDecay)
	b.congestionWindow = max(b.minCongestionWindow, scaleWindow(b.congestionWindow, ecnPathMigrationDecay))
	b.bytesInFlight = 0
	b.isAtFullBandwidth = false
	b.roundsWithoutBandwidthGain = 0
	b.bandwidthAtLastRound = 0
	b.recoveryState = bbrRecoveryStateNotInRecovery
	b.endRecoveryAt = invalidPacketNumber
	b.recoveryWindow = b.maxCongestionWindow
	b.exitProbeRttAt = 0
	b.probeRttRoundPassed = false
	b.enterStartupMode(now)
}

func (state *ecnBBRState) rescaleWindows(oldSize, newSize congestion.ByteCount) {
	state.inflightFloor = scaleByteWindowForDatagramSize(state.inflightFloor, oldSize, newSize)
	state.freezeInflight = scaleByteWindowForDatagramSize(state.freezeInflight, oldSize, newSize)
	state.shrinkInflight = scaleByteWindowForDatagramSize(state.shrinkInflight, oldSize, newSize)
}

func scaleBandwidth(value Bandwidth, factor float64) Bandwidth {
	return Bandwidth(float64(value) * factor)
}

func scaleWindow(value congestion.ByteCount, factor float64) congestion.ByteCount {
	return congestion.ByteCount(float64(value) * factor)
}

func clampWindow(value, minimum, maximum congestion.ByteCount) congestion.ByteCount {
	return min(maximum, max(minimum, value))
}

func timeFraction(value time.Duration, factor float64) time.Duration {
	return time.Duration(float64(value) * factor)
}
