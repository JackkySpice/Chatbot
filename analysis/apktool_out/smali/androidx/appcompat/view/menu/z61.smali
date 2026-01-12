.class public abstract Landroidx/appcompat/view/menu/z61;
.super Ljava/lang/RuntimeException;
.source "SourceFile"


# instance fields
.field public final m:Landroidx/appcompat/view/menu/ev;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ev;Ljava/lang/String;)V
    .locals 1

    const-string v0, "fragment"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Landroidx/appcompat/view/menu/z61;->m:Landroidx/appcompat/view/menu/ev;

    return-void
.end method


# virtual methods
.method public final a()Landroidx/appcompat/view/menu/ev;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/z61;->m:Landroidx/appcompat/view/menu/ev;

    return-object v0
.end method
