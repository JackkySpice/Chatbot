.class public final Landroidx/appcompat/view/menu/jb;
.super Landroidx/appcompat/view/menu/p60;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/ib;


# instance fields
.field public final q:Landroidx/appcompat/view/menu/kb;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/kb;)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/p60;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/jb;->q:Landroidx/appcompat/view/menu/kb;

    return-void
.end method


# virtual methods
.method public b(Ljava/lang/Throwable;)Z
    .locals 1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/w60;->x()Landroidx/appcompat/view/menu/y60;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/y60;->P(Ljava/lang/Throwable;)Z

    move-result p1

    return p1
.end method

.method public bridge synthetic i(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Throwable;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/jb;->w(Ljava/lang/Throwable;)V

    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method

.method public w(Ljava/lang/Throwable;)V
    .locals 1

    iget-object p1, p0, Landroidx/appcompat/view/menu/jb;->q:Landroidx/appcompat/view/menu/kb;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/w60;->x()Landroidx/appcompat/view/menu/y60;

    move-result-object v0

    invoke-interface {p1, v0}, Landroidx/appcompat/view/menu/kb;->u(Landroidx/appcompat/view/menu/kh0;)V

    return-void
.end method
