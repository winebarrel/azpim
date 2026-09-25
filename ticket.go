package azpim

// Ticket names the ticket an activation is for.
//
// A PIM policy can require one. PIM records the number and the system with the
// request but checks neither against anything, so both are free text.
type Ticket struct {
	TicketNumber string `help:"Ticket number recorded with the request, for policies that require one."`
	TicketSystem string `env:"AZPIM_TICKET_SYSTEM" help:"Ticket system recorded with the request, for policies that require one."`
}

// ticketInfo is the ticket as a request carries it.
type ticketInfo struct {
	TicketNumber string `json:"ticketNumber,omitempty"`
	TicketSystem string `json:"ticketSystem,omitempty"`
}

// info leaves the ticket out of the request when none was given, so an
// assignment whose policy asks for no ticket is requested exactly as before.
func (t Ticket) info() *ticketInfo {
	if t.TicketNumber == "" && t.TicketSystem == "" {
		return nil
	}

	return &ticketInfo{TicketNumber: t.TicketNumber, TicketSystem: t.TicketSystem}
}
