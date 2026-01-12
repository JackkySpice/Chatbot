.class public final Landroidx/appcompat/view/menu/yf0$a;
.super Landroidx/appcompat/view/menu/d80;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/jw;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/yf0;-><init>(Ljava/lang/Runnable;Landroidx/appcompat/view/menu/of;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field public final synthetic n:Landroidx/appcompat/view/menu/yf0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/yf0;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/yf0$a;->n:Landroidx/appcompat/view/menu/yf0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/d80;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/g7;)V
    .locals 1

    const-string v0, "backEvent"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/yf0$a;->n:Landroidx/appcompat/view/menu/yf0;

    invoke-static {v0, p1}, Landroidx/appcompat/view/menu/yf0;->c(Landroidx/appcompat/view/menu/yf0;Landroidx/appcompat/view/menu/g7;)V

    return-void
.end method

.method public bridge synthetic i(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/g7;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/yf0$a;->a(Landroidx/appcompat/view/menu/g7;)V

    sget-object p1, Landroidx/appcompat/view/menu/n31;->a:Landroidx/appcompat/view/menu/n31;

    return-object p1
.end method
