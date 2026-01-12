.class public Landroidx/appcompat/view/menu/k5;
.super Landroidx/appcompat/view/menu/s11;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/s11;-><init>()V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/k5;->s0()V

    return-void
.end method


# virtual methods
.method public final s0()V
    .locals 3

    const/4 v0, 0x1

    invoke-virtual {p0, v0}, Landroidx/appcompat/view/menu/s11;->p0(I)Landroidx/appcompat/view/menu/s11;

    new-instance v1, Landroidx/appcompat/view/menu/vq;

    const/4 v2, 0x2

    invoke-direct {v1, v2}, Landroidx/appcompat/view/menu/vq;-><init>(I)V

    invoke-virtual {p0, v1}, Landroidx/appcompat/view/menu/s11;->h0(Landroidx/appcompat/view/menu/o11;)Landroidx/appcompat/view/menu/s11;

    move-result-object v1

    new-instance v2, Landroidx/appcompat/view/menu/qa;

    invoke-direct {v2}, Landroidx/appcompat/view/menu/qa;-><init>()V

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/s11;->h0(Landroidx/appcompat/view/menu/o11;)Landroidx/appcompat/view/menu/s11;

    move-result-object v1

    new-instance v2, Landroidx/appcompat/view/menu/vq;

    invoke-direct {v2, v0}, Landroidx/appcompat/view/menu/vq;-><init>(I)V

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/s11;->h0(Landroidx/appcompat/view/menu/o11;)Landroidx/appcompat/view/menu/s11;

    return-void
.end method
