.class public abstract Landroidx/appcompat/view/menu/ie1;
.super Landroidx/appcompat/view/menu/gk1;
.source "SourceFile"


# instance fields
.field public final d:I

.field public final e:Landroid/os/Bundle;

.field public final synthetic f:Landroidx/appcompat/view/menu/y7;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/y7;ILandroid/os/Bundle;)V
    .locals 1

    iput-object p1, p0, Landroidx/appcompat/view/menu/ie1;->f:Landroidx/appcompat/view/menu/y7;

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-direct {p0, p1, v0}, Landroidx/appcompat/view/menu/gk1;-><init>(Landroidx/appcompat/view/menu/y7;Ljava/lang/Object;)V

    iput p2, p0, Landroidx/appcompat/view/menu/ie1;->d:I

    iput-object p3, p0, Landroidx/appcompat/view/menu/ie1;->e:Landroid/os/Bundle;

    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;)V
    .locals 2

    iget p1, p0, Landroidx/appcompat/view/menu/ie1;->d:I

    const/4 v0, 0x1

    const/4 v1, 0x0

    if-nez p1, :cond_1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/ie1;->g()Z

    move-result p1

    if-nez p1, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/ie1;->f:Landroidx/appcompat/view/menu/y7;

    invoke-static {p1, v0, v1}, Landroidx/appcompat/view/menu/y7;->b0(Landroidx/appcompat/view/menu/y7;ILandroid/os/IInterface;)V

    new-instance p1, Landroidx/appcompat/view/menu/df;

    const/16 v0, 0x8

    invoke-direct {p1, v0, v1}, Landroidx/appcompat/view/menu/df;-><init>(ILandroid/app/PendingIntent;)V

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/ie1;->f(Landroidx/appcompat/view/menu/df;)V

    :cond_0
    return-void

    :cond_1
    iget-object p1, p0, Landroidx/appcompat/view/menu/ie1;->f:Landroidx/appcompat/view/menu/y7;

    invoke-static {p1, v0, v1}, Landroidx/appcompat/view/menu/y7;->b0(Landroidx/appcompat/view/menu/y7;ILandroid/os/IInterface;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/ie1;->e:Landroid/os/Bundle;

    if-eqz p1, :cond_2

    const-string v0, "pendingIntent"

    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;

    move-result-object p1

    move-object v1, p1

    check-cast v1, Landroid/app/PendingIntent;

    :cond_2
    new-instance p1, Landroidx/appcompat/view/menu/df;

    iget v0, p0, Landroidx/appcompat/view/menu/ie1;->d:I

    invoke-direct {p1, v0, v1}, Landroidx/appcompat/view/menu/df;-><init>(ILandroid/app/PendingIntent;)V

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/ie1;->f(Landroidx/appcompat/view/menu/df;)V

    return-void
.end method

.method public final b()V
    .locals 0

    return-void
.end method

.method public abstract f(Landroidx/appcompat/view/menu/df;)V
.end method

.method public abstract g()Z
.end method
