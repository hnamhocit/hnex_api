package ban

import (
	"hnex.com/internal/utils"
)

type SetBanDTO struct {
	Reason      string               `json:"reason" binding:"required"`
	Duration    utils.DurationString `json:"duration" binding:"required"`
	IsPermanent bool                 `json:"is_permanent"`
}
