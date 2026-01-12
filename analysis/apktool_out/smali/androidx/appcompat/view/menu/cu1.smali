.class public final Landroidx/appcompat/view/menu/cu1;
.super Landroidx/appcompat/view/menu/ie1;
.source "SourceFile"


# instance fields
.field public final synthetic g:Landroidx/appcompat/view/menu/y7;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/y7;ILandroid/os/Bundle;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/cu1;->g:Landroidx/appcompat/view/menu/y7;

    const/4 p3, 0x0

    invoke-direct {p0, p1, p2, p3}, Landroidx/appcompat/view/menu/ie1;-><init>(Landroidx/appcompat/view/menu/y7;ILandroid/os/Bundle;)V

    return-void
.end method


# virtual methods
.method public final f(Landroidx/appcompat/view/menu/df;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/cu1;->g:Landroidx/appcompat/view/menu/y7;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/y7;->t()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/cu1;->g:Landroidx/appcompat/view/menu/y7;

    invoke-static {v0}, Landroidx/appcompat/view/menu/y7;->h0(Landroidx/appcompat/view/menu/y7;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/cu1;->g:Landroidx/appcompat/view/menu/y7;

    const/16 v0, 0x10

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/y7;->d0(Landroidx/appcompat/view/menu/y7;I)V

    return-void

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/cu1;->g:Landroidx/appcompat/view/menu/y7;

    iget-object v0, v0, Landroidx/appcompat/view/menu/y7;->A:Landroidx/appcompat/view/menu/y7$c;

    invoke-interface {v0, p1}, Landroidx/appcompat/view/menu/y7$c;->a(Landroidx/appcompat/view/menu/df;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/cu1;->g:Landroidx/appcompat/view/menu/y7;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/y7;->L(Landroidx/appcompat/view/menu/df;)V

    return-void
.end method

.method public final g()Z
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/cu1;->g:Landroidx/appcompat/view/menu/y7;

    iget-object v0, v0, Landroidx/appcompat/view/menu/y7;->A:Landroidx/appcompat/view/menu/y7$c;

    sget-object v1, Landroidx/appcompat/view/menu/df;->q:Landroidx/appcompat/view/menu/df;

    invoke-interface {v0, v1}, Landroidx/appcompat/view/menu/y7$c;->a(Landroidx/appcompat/view/menu/df;)V

    const/4 v0, 0x1

    return v0
.end method
