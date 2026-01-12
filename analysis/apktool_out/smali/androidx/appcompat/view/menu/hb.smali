.class public final Landroidx/appcompat/view/menu/hb;
.super Landroidx/appcompat/view/menu/p60;
.source "SourceFile"


# instance fields
.field public final q:Landroidx/appcompat/view/menu/x9;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/x9;)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/p60;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/hb;->q:Landroidx/appcompat/view/menu/x9;

    return-void
.end method


# virtual methods
.method public bridge synthetic i(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/lang/Throwable;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/hb;->w(Ljava/lang/Throwable;)V

    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method

.method public w(Ljava/lang/Throwable;)V
    .locals 1

    iget-object p1, p0, Landroidx/appcompat/view/menu/hb;->q:Landroidx/appcompat/view/menu/x9;

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/w60;->x()Landroidx/appcompat/view/menu/y60;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/x9;->u(Landroidx/appcompat/view/menu/n60;)Ljava/lang/Throwable;

    move-result-object v0

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/x9;->H(Ljava/lang/Throwable;)V

    return-void
.end method
